package agenthandler

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/runtime-enforcer/internal/resolver"
)

const (
	PolicyDeletionRequeueDelay = 90 * time.Second
)

// WorkloadPolicyHandler reconciles a WorkloadPolicy object.
type WorkloadPolicyHandler struct {
	client.Client

	Scheme        *runtime.Scheme
	logger        *slog.Logger
	resolver      *resolver.Resolver
	isInitialized bool
	initialList   map[ctrl.Request]bool
	initialCount  atomic.Int64
}

func NewWorkloadPolicyHandler(
	client client.Client,
	logger *slog.Logger,
	resolver *resolver.Resolver,
) *WorkloadPolicyHandler {
	return &WorkloadPolicyHandler{
		Client:      client,
		logger:      logger,
		resolver:    resolver,
		initialList: make(map[ctrl.Request]bool),
	}
}

// +kubebuilder:rbac:groups=security.rancher.io,resources=workloadpolicies,verbs=get;list;watch

func (r *WorkloadPolicyHandler) Reconcile(
	ctx context.Context,
	req ctrl.Request,
) (ctrl.Result, error) {
	var err error
	if !r.isInitialized {
		if err = r.createInitialList(ctx); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to create initial list for WorkloadPolicy handler: %w", err)
		}
		r.isInitialized = true
	}

	var wp v1alpha1.WorkloadPolicy
	if err = r.Get(ctx, req.NamespacedName, &wp); err != nil {
		if errors.IsNotFound(err) {
			// The item has been removed.
			if err = r.resolver.HandleWPDelete(&wp); err != nil {
				return ctrl.Result{}, fmt.Errorf(
					"failed to delete WorkloadPolicy '%s/%s': %w",
					req.Namespace,
					req.Name,
					err,
				)
			}

			r.updateInitialList(ctx, req)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("failed to get WorkloadPolicy '%s/%s': %w", req.Namespace, req.Name, err)
	}

	if err = r.resolver.HandleWPUpdate(&wp); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to update WorkloadPolicy '%s/%s': %w", req.Namespace, req.Name, err)
	}

	r.updateInitialList(ctx, req)
	return ctrl.Result{}, nil
}

// createInitialList initializes the internal storage to track the existing WorkloadPolicies.
//
// The tracking contains three steps:
// 1. List all existing WorkloadPolicies and store them in initialList and initialCount, as you see in this function.
// 2. Check if the item being reconciled is in the initialList, if so, remove it from the list and decrease the count.
// 3. Then startup probe checks the count to determine if the handler has synced with all existing WorkloadPolicies.
//
// The logic has to run in a specific timing to avoid race condition between k8s state, controller-runtime cache and workqueue.
// 1. After the controller-runtime cache has synced.
// 2. As part of the reconcile loop.
//
// Some examples:
//   - the initial item is deleted on k8s after we list the policies.
//     If the cache is not synced yet at this point, the item would not be in the cache, so the handler will never become synced.
//   - the item is handled by reconciler loop before we check if it's part of initial items.
//     If we check these information outside of the reconcile loop, we would miss that item and the handler will never become synced.
func (r *WorkloadPolicyHandler) createInitialList(ctx context.Context) error {
	var err error

	var wpList v1alpha1.WorkloadPolicyList
	err = r.List(ctx, &wpList)
	if err != nil {
		return fmt.Errorf("failed to list WorkloadPolicies during initialization: %w", err)
	}
	r.initialCount.Store(int64(len(wpList.Items)))
	for _, wp := range wpList.Items {
		r.initialList[ctrl.Request{
			NamespacedName: client.ObjectKey{
				Name:      wp.Name,
				Namespace: wp.Namespace,
			},
		}] = true
	}

	return nil
}

// HasSynced returns true if the handler has reconciled with all existing WorkloadPolicies.
// It's supposed to be used as part of the startup probe, so we know the enforcement is ready for the old pod to stop during the rolling update.
func (r *WorkloadPolicyHandler) HasSynced() bool {
	return r.initialCount.Load() == 0
}

// updateInitialList removes the item from the initial list and decrease the count if the item is part of the initial list.
// It should be called at the end of each successful Reconcile call.
func (r *WorkloadPolicyHandler) updateInitialList(ctx context.Context, req ctrl.Request) {
	if r.initialList[req] {
		delete(r.initialList, req)
		if count := r.initialCount.Add(-1); count == 0 {
			r.logger.InfoContext(ctx, "WorkloadPolicyHandler has synced with all existing WorkloadPolicies")
		}
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *WorkloadPolicyHandler) SetupWithManager(mgr ctrl.Manager) error {
	err := ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.WorkloadPolicy{}).
		Named("workloadpolicy").
		Complete(r)
	if err != nil {
		return fmt.Errorf("unable to set up WorkloadPolicy handler: %w", err)
	}
	return nil
}
