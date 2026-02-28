package workloadpolicyhandler

import (
	"context"
	"fmt"
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

	Scheme   *runtime.Scheme
	resolver *resolver.Resolver
}

func NewWorkloadPolicyHandler(
	client client.Client,
	resolver *resolver.Resolver,
) *WorkloadPolicyHandler {
	return &WorkloadPolicyHandler{
		Client:   client,
		resolver: resolver,
	}
}

// +kubebuilder:rbac:groups=security.rancher.io,resources=workloadpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.rancher.io,resources=workloadpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.rancher.io,resources=workloadpolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch

func (r *WorkloadPolicyHandler) Reconcile(
	ctx context.Context,
	req ctrl.Request,
) (ctrl.Result, error) {
	var wp v1alpha1.WorkloadPolicy
	if err := r.Get(ctx, req.NamespacedName, &wp); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("failed to get WorkloadPolicy '%s/%s': %w", req.Namespace, req.Name, err)
	}

	if err := r.resolver.HandleWPAdd(&wp); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to handle WorkloadPolicy '%s/%s': %w", req.Namespace, req.Name, err)
	}

	return ctrl.Result{}, nil
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
