package e2e_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/e2e-framework/klient/decoder"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
	"sigs.k8s.io/e2e-framework/pkg/types"
)

// This test verifies the protection is persistent during rolling update of agent.
func getRollingUpdateTest() types.Feature {
	workloadNamespace := envconf.RandomName("workload-namespace", 32)

	return features.New("Rolling update").
		Setup(SetupSharedK8sClient).
		Setup(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			createTestNamespace(ctx, t, workloadNamespace)
			return ctx
		}).
		Setup(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			policy := &v1alpha1.WorkloadPolicy{
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
									"/usr/bin/bash",
									"/usr/bin/ls",
								},
							},
						},
					},
				},
			}
			createAndWaitWP(ctx, t, policy.DeepCopy())
			return ctx
		}).
		Assess("required resources become available", IfRequiredResourcesAreCreated).
		Setup(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			createAndWaitUbuntuDeployment(ctx, t, workloadNamespace, withPolicy("test-policy"),
				decoder.MutateOption(func(obj k8s.Object) error {
					deployment := obj.(*appsv1.Deployment)
					deployment.Spec.Template.Spec.Containers[0].Command = []string{
						"bash",
						"-c",
						"while true; do mkdir /tmp/testdir;done", // this command is supposed to be failing throughout rolling update.
					}
					return nil
				}))
			return ctx
		}).
		Assess("verify that the test directory doesn't exist and mkdir will be blocked",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				r := ctx.Value(key("client")).(*resources.Resources)

				podName, err := findPodByPrefix(ctx, workloadNamespace, "ubuntu-deployment")
				require.NoError(t, err)

				var stdout, stderr bytes.Buffer

				// Run mkdir to verify that it is blocked.
				err = r.ExecInPod(ctx, workloadNamespace, podName, "ubuntu", []string{"mkdir"}, &stdout, &stderr)
				require.Error(t, err)
				require.Empty(t, stdout.String())
				require.Contains(t, stderr.String(), "operation not permitted\n")

				// Verify that the test directory doesn't exist.
				err = r.ExecInPod(
					ctx,
					workloadNamespace,
					podName,
					"ubuntu",
					[]string{"ls", "/tmp/testdir"},
					&stdout,
					&stderr,
				)
				require.Error(t, err)
				require.Empty(t, stdout.String())
				require.Contains(t, stderr.String(), "No such file or directory\n")
				return ctx
			}).
		Assess("rolling update should succeed", func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			r := ctx.Value(key("client")).(*resources.Resources)
			agentDaemonSet := appsv1.DaemonSet{}
			err := r.Get(
				ctx,
				"runtime-enforcer-agent",
				runtimeEnforcerNamespace,
				&agentDaemonSet,
			)
			require.NoError(t, err)
			agentDaemonSet.Spec.Template.Labels["restart"] = "restart" // trigger rolling update

			err = r.Update(ctx, &agentDaemonSet)
			require.NoError(t, err)

			err = wait.For(daemonSetUpToDate(r, &appsv1.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "runtime-enforcer-agent",
					Namespace: runtimeEnforcerNamespace,
				},
			}),
				wait.WithTimeout(DefaultOperationTimeout),
			)
			require.NoError(t, err)
			return ctx
		}).
		Assess("/tmp/testdir should never be created", func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			r := ctx.Value(key("client")).(*resources.Resources)

			podName, err := findPodByPrefix(ctx, workloadNamespace, "ubuntu-deployment")
			require.NoError(t, err)

			var stdout, stderr bytes.Buffer

			err = r.ExecInPod(
				ctx,
				workloadNamespace,
				podName,
				"ubuntu",
				[]string{"ls", "/tmp/testdir"},
				&stdout,
				&stderr,
			)
			require.Error(t, err)
			require.Empty(t, stdout.String())
			require.Contains(t, stderr.String(), "No such file or directory\n")
			return ctx
		}).
		Teardown(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			deleteUbuntuDeployment(ctx, t, workloadNamespace)
			return ctx
		}).Feature()
}
