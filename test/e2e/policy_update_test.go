package e2e_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/e2e-framework/klient/decoder"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
	"sigs.k8s.io/e2e-framework/pkg/types"
)

func getPolicyUpdateTest() types.Feature {
	workloadNamespace := envconf.RandomName("policy-update-ns", 32)

	return features.New("policy-update").
		Setup(SetupSharedK8sClient).
		Setup(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			t.Log("creating test namespace")
			r := ctx.Value(key("client")).(*resources.Resources)

			namespace := corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: workloadNamespace}}

			err := r.Create(ctx, &namespace)
			assert.NoError(t, err, "failed to create test namespace")

			return ctx
		}).
		Setup(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			t.Log("installing test Ubuntu deployment")

			r := ctx.Value(key("client")).(*resources.Resources)

			err := decoder.ApplyWithManifestDir(
				ctx,
				r,
				"./testdata",
				"ubuntu-deployment.yaml",
				[]resources.CreateOption{},
				decoder.MutateNamespace(workloadNamespace),
			)
			assert.NoError(t, err, "failed to apply test data")

			return ctx
		}).
		Assess("required resources become available", IfRequiredResourcesAreCreated).
		Assess("policy update with new executables is enforced correctly",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				r := ctx.Value(key("client")).(*resources.Resources)

				var podName string
				var pods corev1.PodList
				err := r.WithNamespace(workloadNamespace).List(ctx, &pods)
				require.NoError(t, err)

				for _, v := range pods.Items {
					if strings.HasPrefix(v.Name, "ubuntu-deployment") {
						podName = v.Name
						break
					}
				}
				require.NotEmpty(t, podName, "ubuntu pod not found")

				t.Log("creating initial policy with limited executables")
				policy := v1alpha1.WorkloadPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-policy",
						Namespace: workloadNamespace,
					},
					Spec: v1alpha1.WorkloadPolicySpec{
						Mode: "protect",
						RulesByContainer: map[string]*v1alpha1.WorkloadPolicyRules{
							"ubuntu": {
								Executables: v1alpha1.WorkloadPolicyExecutables{
									Allowed: []string{
										"/usr/bin/ls",
										"/usr/bin/bash",
										"/usr/bin/sleep",
									},
								},
							},
						},
					},
				}

				err = r.Create(ctx, &policy)
				require.NoError(t, err, "failed to create initial policy")

				waitForWorkloadPolicyStatusToBeUpdated(ctx, t, policy.DeepCopy())

				t.Log("verifying /usr/bin/cat is blocked before update")
				var stdout, stderr bytes.Buffer
				err = r.ExecInPod(
					ctx,
					workloadNamespace,
					podName,
					"ubuntu",
					[]string{"/usr/bin/cat", "/etc/hostname"},
					&stdout,
					&stderr,
				)
				require.Error(t, err, "/usr/bin/cat should be blocked")
				require.Contains(t, stderr.String(), "operation not permitted")

				t.Log("updating policy to add /usr/bin/cat")

				var updatedPolicy v1alpha1.WorkloadPolicy
				err = r.Get(ctx, "test-policy", workloadNamespace, &updatedPolicy)
				require.NoError(t, err, "failed to get policy for update")

				updatedPolicy.Spec.RulesByContainer["ubuntu"].Executables.Allowed = []string{
					"/usr/bin/ls",
					"/usr/bin/bash",
					"/usr/bin/sleep",
					"/usr/bin/cat",
				}

				err = r.Update(ctx, &updatedPolicy)
				require.NoError(t, err, "failed to update policy")

				waitForWorkloadPolicyStatusToBeUpdated(ctx, t, updatedPolicy.DeepCopy())

				t.Log("verifying /usr/bin/cat is allowed after update")
				stdout.Reset()
				stderr.Reset()
				err = r.ExecInPod(
					ctx,
					workloadNamespace,
					podName,
					"ubuntu",
					[]string{"/usr/bin/cat", "/etc/hostname"},
					&stdout,
					&stderr,
				)
				require.NoError(t, err, "/usr/bin/cat should be allowed after policy update")
				require.NotEmpty(t, stdout.String(), "cat should have produced output")

				t.Log("verifying /usr/bin/apt is still blocked")
				stdout.Reset()
				stderr.Reset()
				err = r.ExecInPod(
					ctx,
					workloadNamespace,
					podName,
					"ubuntu",
					[]string{"/usr/bin/apt", "update"},
					&stdout,
					&stderr,
				)
				require.Error(t, err, "/usr/bin/apt should still be blocked")
				require.Contains(t, stderr.String(), "operation not permitted")

				t.Log("cleaning up policy")
				err = r.Delete(ctx, &updatedPolicy)
				require.NoError(t, err, "failed to delete policy")

				return ctx
			}).
		Assess("policy update can add enforcement for a new container",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				r := ctx.Value(key("client")).(*resources.Resources)

				policyName := "test-policy-add-container"
				podName := "multi-container-pod-add"

				t.Log("creating multi-container pod with policy label (only main initially protected)")

				pod := corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      podName,
						Namespace: workloadNamespace,
						Labels: map[string]string{
							v1alpha1.PolicyLabelKey: policyName,
						},
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name:    "main",
								Image:   "ubuntu",
								Command: []string{"sleep", "3600"},
							},
							{
								Name:    "sidecar",
								Image:   "ubuntu",
								Command: []string{"sleep", "3600"},
							},
						},
					},
				}

				err := r.Create(ctx, &pod)
				require.NoError(t, err, "failed to create multi-container pod for add-container scenario")

				t.Log("creating initial policy protecting only main container")
				policy := v1alpha1.WorkloadPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      policyName,
						Namespace: workloadNamespace,
					},
					Spec: v1alpha1.WorkloadPolicySpec{
						Mode: "protect",
						RulesByContainer: map[string]*v1alpha1.WorkloadPolicyRules{
							"main": {
								Executables: v1alpha1.WorkloadPolicyExecutables{
									Allowed: []string{
										"/usr/bin/ls",
										"/usr/bin/bash",
										"/usr/bin/sleep",
									},
								},
							},
							// sidecar intentionally omitted at first
						},
					},
				}

				err = r.Create(ctx, &policy)
				require.NoError(t, err, "failed to create initial policy for add-container scenario")

				waitForWorkloadPolicyStatusToBeUpdated()

				// 1. Verify that /usr/bin/mkdir is blocked in main but allowed in sidecar
				t.Log("verifying /usr/bin/mkdir is blocked in main and allowed in sidecar before update")

				var stdout, stderr bytes.Buffer

				stdout.Reset()
				stderr.Reset()
				err = r.ExecInPod(
					ctx,
					workloadNamespace,
					podName,
					"main",
					[]string{"/usr/bin/mkdir", "/tmp/main-dir-add"},
					&stdout,
					&stderr,
				)
				require.Error(t, err, "mkdir should be blocked in main container before adding sidecar rules")
				require.Contains(
					t,
					stderr.String(),
					"operation not permitted",
					"stderr should contain 'operation not permitted' when mkdir is blocked in main container before update",
				)

				stdout.Reset()
				stderr.Reset()
				err = r.ExecInPod(
					ctx,
					workloadNamespace,
					podName,
					"sidecar",
					[]string{"/usr/bin/mkdir", "/tmp/sidecar-dir-add"},
					&stdout,
					&stderr,
				)
				require.NoError(t, err, "mkdir should be allowed in sidecar container before it is added to the policy")

				// 2. Update the policy to add the sidecar container to RulesByContainer
				t.Log("updating policy to add sidecar container rules")

				var updatedPolicy v1alpha1.WorkloadPolicy
				err = r.Get(ctx, policyName, workloadNamespace, &updatedPolicy)
				require.NoError(t, err, "failed to get policy for add-container update")

				updatedPolicy.Spec.RulesByContainer["sidecar"] = &v1alpha1.WorkloadPolicyRules{
					Executables: v1alpha1.WorkloadPolicyExecutables{
						Allowed: []string{
							"/usr/bin/ls",
							"/usr/bin/bash",
							"/usr/bin/sleep",
						},
					},
				}

				err = r.Update(ctx, &updatedPolicy)
				require.NoError(t, err, "failed to update policy to add sidecar rules")

				waitForWorkloadPolicyStatusToBeUpdated()

				// 3. Verify both main and sidecar are now protected (mkdir blocked in both)
				t.Log("verifying both main and sidecar are protected after update")

				stdout.Reset()
				stderr.Reset()
				err = r.ExecInPod(
					ctx,
					workloadNamespace,
					podName,
					"main",
					[]string{"/usr/bin/mkdir", "/tmp/main-dir-add-2"},
					&stdout,
					&stderr,
				)
				require.Error(t, err, "mkdir should still be blocked in main container after adding sidecar rules")
				require.Contains(
					t,
					stderr.String(),
					"operation not permitted",
					"stderr should contain 'operation not permitted' when mkdir is blocked in main container after update",
				)

				stdout.Reset()
				stderr.Reset()
				err = r.ExecInPod(
					ctx,
					workloadNamespace,
					podName,
					"sidecar",
					[]string{"/usr/bin/mkdir", "/tmp/sidecar-dir-add-2"},
					&stdout,
					&stderr,
				)
				require.Error(t, err, "mkdir should be blocked in sidecar container after it is added to the policy")
				require.Contains(
					t,
					stderr.String(),
					"operation not permitted",
					"stderr should contain 'operation not permitted' when mkdir is blocked in sidecar container after update",
				)

				t.Log("cleaning up pod")
				err = r.Delete(ctx, &pod)
				require.NoError(t, err, "failed to delete pod in add-container scenario")

				t.Log("cleaning up policy")
				err = r.Delete(ctx, &updatedPolicy)
				require.NoError(t, err, "failed to delete policy in add-container scenario")

				return ctx
			}).
		Assess("policy update can disable enforcement for a single container",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				r := ctx.Value(key("client")).(*resources.Resources)

				policyName := "test-policy-disable-container"
				podName := "multi-container-pod"

				t.Log("creating multi-container pod with policy label")

				pod := corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      podName,
						Namespace: workloadNamespace,
						Labels: map[string]string{
							v1alpha1.PolicyLabelKey: policyName,
						},
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name:    "main",
								Image:   "ubuntu",
								Command: []string{"sleep", "3600"},
							},
							{
								Name:    "sidecar",
								Image:   "ubuntu",
								Command: []string{"sleep", "3600"},
							},
						},
						RestartPolicy: corev1.RestartPolicyNever,
					},
				}

				err := r.Create(ctx, &pod)
				require.NoError(t, err, "failed to create multi-container pod")

				t.Log("creating initial policy protecting both containers")
				policy := v1alpha1.WorkloadPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      policyName,
						Namespace: workloadNamespace,
					},
					Spec: v1alpha1.WorkloadPolicySpec{
						Mode: "protect",
						RulesByContainer: map[string]*v1alpha1.WorkloadPolicyRules{
							"main": {
								Executables: v1alpha1.WorkloadPolicyExecutables{
									Allowed: []string{
										"/usr/bin/ls",
										"/usr/bin/bash",
										"/usr/bin/sleep",
									},
								},
							},
							"sidecar": {
								Executables: v1alpha1.WorkloadPolicyExecutables{
									Allowed: []string{
										"/usr/bin/ls",
										"/usr/bin/bash",
										"/usr/bin/sleep",
									},
								},
							},
						},
					},
				}

				err = r.Create(ctx, &policy)
				require.NoError(t, err, "failed to create initial policy")

				waitForWorkloadPolicyStatusToBeUpdated()

				// 1. Verify that /usr/bin/mkdir is blocked in both containers
				t.Log("verifying /usr/bin/mkdir is initially blocked in both containers")

				var stdout, stderr bytes.Buffer

				stdout.Reset()
				stderr.Reset()
				err = r.ExecInPod(
					ctx,
					workloadNamespace,
					podName,
					"main",
					[]string{"/usr/bin/mkdir", "/tmp/main-dir"},
					&stdout,
					&stderr,
				)
				require.Error(t, err, "mkdir should be blocked in main container before update")
				require.Contains(
					t,
					stderr.String(),
					"operation not permitted",
					"stderr should contain 'operation not permitted' when mkdir is blocked in main container",
				)

				stdout.Reset()
				stderr.Reset()
				err = r.ExecInPod(
					ctx,
					workloadNamespace,
					podName,
					"sidecar",
					[]string{"/usr/bin/mkdir", "/tmp/sidecar-dir"},
					&stdout,
					&stderr,
				)
				require.Error(t, err, "mkdir should be blocked in sidecar container before update")
				require.Contains(
					t,
					stderr.String(),
					"operation not permitted",
					"stderr should contain 'operation not permitted' when mkdir is blocked in sidecar container",
				)

				// 2. Update the policy to remove the sidecar container from RulesByContainer
				t.Log("updating policy to remove sidecar container rules")

				var updatedPolicy v1alpha1.WorkloadPolicy
				err = r.Get(ctx, policyName, workloadNamespace, &updatedPolicy)
				require.NoError(t, err, "failed to get policy for update")

				delete(updatedPolicy.Spec.RulesByContainer, "sidecar")

				err = r.Update(ctx, &updatedPolicy)
				require.NoError(t, err, "failed to update policy to remove sidecar rules")

				waitForWorkloadPolicyStatusToBeUpdated()

				// 3. Verify main is still protected (mkdir blocked) while sidecar is now unprotected (mkdir allowed)
				t.Log("verifying main container remains protected and sidecar is unprotected after update")

				stdout.Reset()
				stderr.Reset()
				err = r.ExecInPod(
					ctx,
					workloadNamespace,
					podName,
					"main",
					[]string{"/usr/bin/mkdir", "/tmp/main-dir-2"},
					&stdout,
					&stderr,
				)
				require.Error(t, err, "mkdir should still be blocked in main container after update")
				require.Contains(
					t,
					stderr.String(),
					"operation not permitted",
					"stderr should contain 'operation not permitted' when mkdir is blocked in main container after update",
				)

				stdout.Reset()
				stderr.Reset()
				err = r.ExecInPod(
					ctx,
					workloadNamespace,
					podName,
					"sidecar",
					[]string{"/usr/bin/mkdir", "/tmp/sidecar-dir-2"},
					&stdout,
					&stderr,
				)
				require.NoError(t, err, "mkdir should be allowed in sidecar container after its rules are removed")

				t.Log("cleaning up pod")
				err = r.Delete(ctx, &pod)
				require.NoError(t, err, "failed to delete pod")

				t.Log("cleaning up policy")
				err = r.Delete(ctx, &updatedPolicy)
				require.NoError(t, err, "failed to delete policy")

				return ctx
			}).
		Teardown(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			t.Log("uninstalling test resources")
			r := ctx.Value(key("client")).(*resources.Resources)
			err := decoder.DeleteWithManifestDir(
				ctx,
				r,
				"./testdata",
				"ubuntu-deployment.yaml",
				[]resources.DeleteOption{},
				decoder.MutateNamespace(workloadNamespace),
			)
			assert.NoError(t, err, "failed to delete test data")

			return ctx
		}).Feature()
}
