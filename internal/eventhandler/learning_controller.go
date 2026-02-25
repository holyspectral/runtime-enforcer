package eventhandler

import (
	"context"
	"fmt"
	"sync"
	"time"

	securityv1alpha1 "github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/runtime-enforcer/internal/eventscraper"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

// DefaultEventChannelBufferSize defines the channel buffer size used to
// deliver events to learning_controller.
// This is a arbitrary number right now and can be fine-tuned or made configurable in the future.
// On a simple kind cluster we saw more than 4200 process exec during the initial process cache dump, so this seems a reasonable default for now.
const DefaultEventChannelBufferSize = 4096

// GetWorkloadPolicyProposalName returns the name of WorkloadPolicyProposal
// based on a high level resource and its name.
func GetWorkloadPolicyProposalName(kind string, resourceName string) (string, error) {
	var shortname string
	switch kind {
	case "Deployment":
		shortname = "deploy"
	case "ReplicaSet":
		shortname = "rs"
	case "DaemonSet":
		shortname = "ds"
	case "CronJob":
		shortname = "cronjob"
	case "Job":
		shortname = "job"
	case "StatefulSet":
		shortname = "sts"
	default:
		return "", fmt.Errorf("unknown kind: %s", kind)
	}
	ret := shortname + "-" + resourceName

	// The max name length in k8s
	if len(ret) > validation.DNS1123SubdomainMaxLength {
		return "", fmt.Errorf("the name %s exceeds the maximum name length", ret)
	}

	return shortname + "-" + resourceName, nil
}

type LearningEventCache struct {
	mu            sync.Mutex
	processEvents map[eventscraper.KubeWorkload][]eventscraper.KubeProcessInfo
}

func NewLearningEventCache() *LearningEventCache {
	return &LearningEventCache{
		processEvents: make(map[eventscraper.KubeWorkload][]eventscraper.KubeProcessInfo),
	}
}

func (c *LearningEventCache) MergeEvent(event eventscraper.KubeProcessInfo) {
	req := eventscraper.KubeWorkload{
		Namespace:    event.Namespace,
		Workload:     event.Workload,
		WorkloadKind: event.WorkloadKind,
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.processEvents[req] = append(c.processEvents[req], event)
}

func (c *LearningEventCache) GetEvents(req eventscraper.KubeWorkload) []eventscraper.KubeProcessInfo {
	c.mu.Lock()
	defer c.mu.Unlock()
	events := c.processEvents[req]
	return events
}

func (c *LearningEventCache) Purge(req eventscraper.KubeWorkload) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.processEvents, req)
}

type LearningReconciler struct {
	client.Client

	Scheme    *runtime.Scheme
	eventChan chan event.TypedGenericEvent[eventscraper.KubeProcessInfo]
	tracer    trace.Tracer
	// OwnerRefEnricher can be overridden during testing
	OwnerRefEnricher func(wp *securityv1alpha1.WorkloadPolicyProposal, workloadKind string, workload string)
	eventCache       *LearningEventCache
}

func NewLearningReconciler(client client.Client, eventCache *LearningEventCache) *LearningReconciler {
	if eventCache == nil {
		eventCache = NewLearningEventCache()
	}
	return &LearningReconciler{
		Client:    client,
		eventChan: make(chan event.TypedGenericEvent[eventscraper.KubeProcessInfo], DefaultEventChannelBufferSize),
		tracer:    otel.Tracer("runtime-enforcer-learner"),
		OwnerRefEnricher: func(wp *securityv1alpha1.WorkloadPolicyProposal, workloadKind string, workload string) {
			wp.OwnerReferences = []metav1.OwnerReference{
				{
					Kind: workloadKind,
					Name: workload,
				},
			}
		},
		eventCache: eventCache,
	}
}

// kubebuilder annotations for accessing policy proposals.
// +kubebuilder:rbac:groups=security.rancher.io,resources=workloadpolicyproposals,verbs=create;get;list;watch;update;patch

// Reconcile receives learning events and creates/updates WorkloadPolicyProposal resources accordingly.
func (r *LearningReconciler) Reconcile(
	ctx context.Context,
	req eventscraper.KubeWorkload,
) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	log.V(3).Info("Reconciling", "req", req) //nolint:mnd // 3 is the verbosity level for detailed debug info

	var err error
	var proposalName string

	if req.WorkloadKind == "Pod" {
		// We don't support learning on standalone pods

		log.V(3).Info( //nolint:mnd // 3 is the verbosity level for detailed debug info
			"Ignoring learning event",
			"workload", req.Workload,
			"workload_kind", req.WorkloadKind,
		)

		return ctrl.Result{}, nil
	}

	processEvts := r.eventCache.GetEvents(req)

	proposalName, err = GetWorkloadPolicyProposalName(req.WorkloadKind, req.Workload)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to get proposal name: %w", err)
	}

	policyProposal := &securityv1alpha1.WorkloadPolicyProposal{
		ObjectMeta: metav1.ObjectMeta{
			Name:      proposalName,
			Namespace: req.Namespace,
		},
	}

	var result controllerutil.OperationResult

	if result, err = controllerutil.CreateOrUpdate(ctx, r.Client, policyProposal, func() error {
		// We don't learn any new process if the policy proposal was promoted
		// to an actual policy
		labels := policyProposal.GetLabels()
		if labels[securityv1alpha1.ApprovalLabelKey] == "true" {
			return nil
		}

		for _, evt := range processEvts {
			if err = policyProposal.AddProcess(evt.ContainerName, evt.ExecutablePath); err != nil {
				return fmt.Errorf("failed to add process to policy proposal: %w", err)
			}
		}

		// If the owner reference is already there we do nothing.
		// We should always have the owner reference populated unless we are creating the resource for the first time.
		if len(policyProposal.OwnerReferences) != 0 {
			return nil
		}

		// if we don't populate a partial owner reference here the webhook won't be able to populate the owner reference because it doesn't know who is the owner.
		r.OwnerRefEnricher(policyProposal, req.WorkloadKind, req.Workload)
		return nil
	}); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to run CreateOrUpdate: %w", err)
	}

	if result != controllerutil.OperationResultNone {
		// clean up the event queue since they're all merged.
		r.eventCache.Purge(req)

		// Emit trace when a new process is learned.
		var span trace.Span
		now := time.Now()
		_, span = r.tracer.Start(ctx, "process learned")
		span.SetAttributes(
			attribute.String("evt.time", now.Format(time.RFC3339)),
			attribute.Int64("evt.rawtime", now.UnixNano()),
			attribute.String("k8s.ns.name", req.Namespace),
			attribute.String("k8s.workload.kind", req.WorkloadKind),
			attribute.String("k8s.workload.name", req.Workload),
			// TODO
			// attribute.String("container.name", req.ContainerName),
			// attribute.String("proc.exepath", req.ExecutablePath),
		)
		span.End()
	}

	return ctrl.Result{}, nil
}

func (r *LearningReconciler) EnqueueEvent(evt eventscraper.KubeProcessInfo) {
	r.eventChan <- event.TypedGenericEvent[eventscraper.KubeProcessInfo]{Object: evt}
}

// ProcessEventHandler implements handler.TypedEventHandler[eventscraper.KubeProcessInfo, eventscraper.KubeProcessInfo].
type ProcessEventHandler struct {
	eventCache *LearningEventCache
}

func (e ProcessEventHandler) Create(
	_ context.Context,
	_ event.TypedCreateEvent[eventscraper.KubeProcessInfo],
	_ workqueue.TypedRateLimitingInterface[eventscraper.KubeWorkload],
) {

}

func (e ProcessEventHandler) Update(
	_ context.Context,
	_ event.TypedUpdateEvent[eventscraper.KubeProcessInfo],
	_ workqueue.TypedRateLimitingInterface[eventscraper.KubeWorkload],
) {

}

func (e ProcessEventHandler) Delete(
	_ context.Context,
	_ event.TypedDeleteEvent[eventscraper.KubeProcessInfo],
	_ workqueue.TypedRateLimitingInterface[eventscraper.KubeWorkload],
) {

}

func (e ProcessEventHandler) Generic(
	_ context.Context,
	evt event.TypedGenericEvent[eventscraper.KubeProcessInfo],
	q workqueue.TypedRateLimitingInterface[eventscraper.KubeWorkload],
) {
	e.eventCache.MergeEvent(evt.Object)
	q.AddRateLimited(eventscraper.KubeWorkload{
		Namespace:    evt.Object.Namespace,
		Workload:     evt.Object.Workload,
		WorkloadKind: evt.Object.WorkloadKind,
	})
}

// SetupWithManager sets up the controller with the Manager.
func (r *LearningReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return builder.TypedControllerManagedBy[eventscraper.KubeWorkload](mgr).
		Named("learningEvent").
		WatchesRawSource(
			source.TypedChannel(
				r.eventChan,
				&ProcessEventHandler{eventCache: r.eventCache},
			),
		).
		Complete(r)
}
