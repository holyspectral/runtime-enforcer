package controller

import (
	"context"
	"fmt"

	"github.com/neuvector/runtime-enforcer/api/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

type PolicyWebhook struct{}

// Default adds a finalizer to WorkloadPolicy on CREATE and UPDATE events.
func (w *PolicyWebhook) Default(ctx context.Context, obj runtime.Object) error {
	logger := log.FromContext(ctx)

	policy, ok := obj.(*v1alpha1.WorkloadPolicy)
	if !ok {
		return fmt.Errorf("expected a WorkloadPolicy but got a %T", obj)
	}

	// Check if the policy is being deleted
	if !policy.DeletionTimestamp.IsZero() {
		// No need to default a deleting object
		return nil
	}

	// Add finalizer to ensure a policy cannot be deleted while in use by pods
	// This handles both CREATE events and UPDATE events (e.g., when a proposal is promoted to a policy)
	if !controllerutil.ContainsFinalizer(policy, v1alpha1.WorkloadPolicyFinalizer) {
		controllerutil.AddFinalizer(policy, v1alpha1.WorkloadPolicyFinalizer)
		logger.Info("added finalizer to WorkloadPolicy", "name", policy.GetName())
	}

	return nil
}
