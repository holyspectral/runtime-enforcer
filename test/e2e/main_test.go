package e2e_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/runtime-enforcer/internal/types/policymode"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
	"sigs.k8s.io/e2e-framework/pkg/types"
)

func getMainTest() types.Feature {
	return features.New("Main").
		Setup(SetupSharedK8sClient).
		Setup(SetupTestNamespace).
		Setup(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			createAndWaitUbuntuDeployment(ctx, t)
			return ctx
		}).
		Assess("required resources become available", IfRequiredResourcesAreCreated).
		Assess("the workload policy proposal is created successfully for the ubuntu pod",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				r := getClient(ctx)

				proposal := v1alpha1.WorkloadPolicyProposal{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "deploy-ubuntu-deployment",
						Namespace: getNamespace(ctx),
					},
				}
				err := wait.For(conditions.New(r).ResourceMatch(
					&proposal,
					func(object k8s.Object) bool {
						obj := object.(*v1alpha1.WorkloadPolicyProposal)
						if obj.OwnerReferences[0].Name == "ubuntu-deployment" &&
							obj.OwnerReferences[0].Kind == "Deployment" {
							return true
						}
						return false
					}),
					wait.WithTimeout(DefaultOperationTimeout),
				)
				require.NoError(t, err)

				return context.WithValue(ctx, key("group"), proposal.Name)
			}).
		Assess("the running process is learned",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				id := ctx.Value(key("group")).(string)
				r := getClient(ctx)

				t.Log("waiting for workload policy proposal to be created: ", id)

				proposal := v1alpha1.WorkloadPolicyProposal{
					ObjectMeta: metav1.ObjectMeta{
						Name:      id,
						Namespace: getNamespace(ctx),
					},
				}

				// There are two categories of processes to be learned:
				// 1. /usr/bin/bash: the container entrypoint.
				// 2. /usr/bin/sleep & /usr/bin/ls: the commands the container executes
				t.Log("waiting for processes to be learned")

				err := wait.For(conditions.New(r).ResourceMatch(
					&proposal,
					func(_ k8s.Object) bool {
						rules := proposal.Spec.RulesByContainer["ubuntu"]

						return verifyUbuntuLearnedProcesses(rules.Executables.Allowed)
					}),
					wait.WithTimeout(DefaultOperationTimeout),
				)
				require.NoError(t, err)

				return context.WithValue(ctx, key("proposal"), &proposal)
			}).
		Assess("a proposal is promoted to a workload policy and the WP is created",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				proposal := ctx.Value(key("proposal")).(*v1alpha1.WorkloadPolicyProposal)
				policy := v1alpha1.WorkloadPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-policy",
						Namespace: proposal.ObjectMeta.Namespace,
					},
					Spec: v1alpha1.WorkloadPolicySpec{
						Mode: policymode.ProtectString,
						RulesByContainer: map[string]*v1alpha1.WorkloadPolicyRules{
							"ubuntu": {
								Executables: v1alpha1.WorkloadPolicyExecutables{
									Allowed: proposal.Spec.RulesByContainer["ubuntu"].Executables.Allowed,
								},
							},
						},
					},
				}
				createAndWaitWP(ctx, t, policy.DeepCopy())
				return context.WithValue(ctx, key("policy"), &policy)
			}).
		Assess("update the workload to apply policy",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				// Delete the ubuntu deployment
				deleteUbuntuDeployment(ctx, t)

				// Create the ubuntu deployment again with policy label assigned.
				createAndWaitUbuntuDeployment(ctx, t, withPolicy("test-policy"))
				return ctx
			}).
		Assess("pod exec will be blocked",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				podName, err := findUbuntuDeploymentPod(ctx, func(pod corev1.Pod) bool {
					return pod.Labels[v1alpha1.PolicyLabelKey] == "test-policy"
				})
				require.NoError(t, err)
				requireExecBlockedInCurrentNamespace(ctx, t, podName, "ubuntu", []string{"mkdir"})
				return ctx
			}).
		Assess("the WorkloadPolicy has the finalizer set",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				r := getClient(ctx)
				policy := &v1alpha1.WorkloadPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-policy",
						Namespace: getNamespace(ctx),
					},
				}

				err := wait.For(
					conditions.New(r).ResourceMatch(
						policy,
						func(obj k8s.Object) bool {
							wp := obj.(*v1alpha1.WorkloadPolicy)
							return slices.Contains(wp.Finalizers, v1alpha1.WorkloadPolicyFinalizer)
						},
					),
					wait.WithTimeout(DefaultOperationTimeout),
				)
				require.NoError(t, err, "WorkloadPolicy finalizer is not set")

				return ctx
			}).
		Assess("Verify a non-referenced WorkloadPolicy can be deleted",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				var err error
				r := getClient(ctx)
				nonReferencedPolicyName := "non-referenced-wp"

				// Create a new WorkloadPolicy
				nonReferencedPolicy := v1alpha1.WorkloadPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      nonReferencedPolicyName,
						Namespace: getNamespace(ctx),
					},
					Spec: v1alpha1.WorkloadPolicySpec{
						Mode: policymode.MonitorString,
						RulesByContainer: map[string]*v1alpha1.WorkloadPolicyRules{
							"ubuntu": {
								Executables: v1alpha1.WorkloadPolicyExecutables{
									Allowed: []string{"/bin/true"},
								},
							},
						},
					},
				}
				require.NoError(
					t,
					r.Create(ctx, &nonReferencedPolicy),
					"failed to create non-referenced WorkloadPolicy",
				)

				err = r.Delete(ctx, &nonReferencedPolicy)
				require.NoError(t, err, "failed to delete non-referenced WorkloadPolicy")

				// Wait for the WorkloadPolicy to be deleted
				err = wait.For(
					conditions.New(r).ResourceDeleted(&nonReferencedPolicy),
					wait.WithTimeout(time.Minute*2),
					wait.WithInterval(time.Second*5),
				)
				require.NoError(
					t,
					err,
					"policy was not deleted within timeout",
				)

				return ctx
			}).
		Assess("Verify a referenced WorkloadPolicy cannot be deleted",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				var err error
				r := getClient(ctx)
				referencedPolicyName := "referenced-wp"
				podName := "referenced-wp-pod"

				// Create a new WorkloadPolicy
				referencedPolicy := v1alpha1.WorkloadPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      referencedPolicyName,
						Namespace: getNamespace(ctx),
					},
					Spec: v1alpha1.WorkloadPolicySpec{
						Mode: policymode.MonitorString,
						RulesByContainer: map[string]*v1alpha1.WorkloadPolicyRules{
							"ubuntu": {
								Executables: v1alpha1.WorkloadPolicyExecutables{
									Allowed: []string{"/bin/true"},
								},
							},
						},
					},
				}
				require.NoError(
					t,
					r.Create(ctx, &referencedPolicy),
					"failed to create referenced WorkloadPolicy",
				)

				pod := corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      podName,
						Namespace: getNamespace(ctx),
						Labels: map[string]string{
							v1alpha1.PolicyLabelKey: referencedPolicyName,
						},
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name:  "pause",
								Image: "registry.k8s.io/pause",
							},
						},
					},
				}
				require.NoError(
					t,
					r.Create(ctx, &pod),
					"failed to create Pod",
				)

				// Try to delete the referenced policy
				require.NoError(
					t,
					r.Delete(ctx, &referencedPolicy),
					"failed to issue delete request for WorkloadPolicy",
				)

				// Verify the policy still exists (should not be deleted due to finalizer)
				err = wait.For(
					conditions.New(r).ResourceMatch(
						&referencedPolicy,
						func(obj k8s.Object) bool {
							wp := obj.(*v1alpha1.WorkloadPolicy)
							return wp.DeletionTimestamp != nil &&
								slices.Contains(wp.Finalizers, v1alpha1.WorkloadPolicyFinalizer)
						},
					),
					wait.WithTimeout(30*time.Second),
					wait.WithInterval(5*time.Second),
				)
				require.NoError(
					t,
					err,
					"WorkloadPolicy should still exist while referenced by Pod",
				)

				// Clean up pod, then policy should be deleted automatically
				require.NoError(
					t,
					r.Delete(ctx, &pod),
					"failed to delete Pod",
				)

				// Wait for the pod to be deleted
				err = wait.For(
					conditions.New(r).ResourceDeleted(&pod),
					wait.WithTimeout(2*time.Minute),
					wait.WithInterval(5*time.Second),
				)
				require.NoError(
					t,
					err,
					"Pod was not deleted within timeout",
				)

				// Now the policy should be deleted automatically
				err = wait.For(
					conditions.New(r).ResourceDeleted(&referencedPolicy),
					wait.WithTimeout(2*time.Minute),
					wait.WithInterval(5*time.Second),
				)
				require.NoError(
					t,
					err,
					"WorkloadPolicy should be deleted after Pod is removed",
				)

				return ctx
			}).
		Teardown(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			deleteUbuntuDeployment(ctx, t)
			return ctx
		}).Feature()
}
