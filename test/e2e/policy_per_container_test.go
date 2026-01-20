package e2e_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/neuvector/runtime-enforcer/api/v1alpha1"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
	"sigs.k8s.io/e2e-framework/pkg/types"
)

func getPolicyPerContainerTest() types.Feature {
	workloadNamespace := envconf.RandomName("policy-per-container-namespace", 32)
	policyName := "per-container-policy"
	podName := "test-pod-init-main"

	return features.New("policy per container").
		Setup(SetupSharedK8sClient).
		Setup(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			t.Log("creating test namespace")
			r := ctx.Value(key("client")).(*resources.Resources)

			namespace := corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: workloadNamespace}}

			err := r.Create(ctx, &namespace)
			require.NoError(t, err, "failed to create test namespace")

			return ctx
		}).
		Setup(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			t.Log("creating workload policy with per-container rules")

			r := ctx.Value(key("client")).(*resources.Resources)

			// Create a policy that allows:
			// - init-container: bash and sleep
			// - main-container: ls and sleep
			policy := v1alpha1.WorkloadPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      policyName,
					Namespace: workloadNamespace,
				},
				Spec: v1alpha1.WorkloadPolicySpec{
					Mode: "protect",
					RulesByContainer: map[string]*v1alpha1.WorkloadPolicyRules{
						"init-container": {
							Executables: v1alpha1.WorkloadPolicyExecutables{
								Allowed: []string{
									"/usr/bin/bash",
									"/usr/bin/sleep",
								},
							},
						},
						"main-container": {
							Executables: v1alpha1.WorkloadPolicyExecutables{
								Allowed: []string{
									"/usr/bin/ls",
									"/usr/bin/sleep",
								},
							},
						},
					},
				},
			}

			err := r.Create(ctx, &policy)
			require.NoError(t, err, "failed to create workload policy")

			waitForWorkloadPolicyStatusToBeUpdated()

			return ctx
		}).
		Assess("required resources become available", IfRequiredResourcesAreCreated).
		Assess("pod with init and main containers is created",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				t.Log("creating pod with init container and main container")

				r := ctx.Value(key("client")).(*resources.Resources)

				pod := corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      podName,
						Namespace: workloadNamespace,
						Labels: map[string]string{
							v1alpha1.PolicyLabelKey: policyName,
						},
					},
					Spec: corev1.PodSpec{
						InitContainers: []corev1.Container{
							{
								Name:  "init-container",
								Image: "ubuntu",
								Command: []string{
									"bash", "-c",
									"echo 'Init container completed successfully' && sleep 2",
								},
							},
						},
						Containers: []corev1.Container{
							{
								Name:    "main-container",
								Image:   "ubuntu",
								Command: []string{"sleep", "3600"},
							},
						},
						RestartPolicy: corev1.RestartPolicyNever,
					},
				}

				err := r.Create(ctx, &pod)
				require.NoError(t, err, "failed to create pod")

				err = wait.For(
					conditions.New(r).PodReady(&pod),
					wait.WithTimeout(DefaultOperationTimeout),
				)
				require.NoError(t, err, "pod did not become ready")

				err = r.Get(ctx, podName, workloadNamespace, &pod)
				require.NoError(t, err, "failed to get pod")

				// The init container completed successfully, which means bash was allowed to run
				require.NotEmpty(t, pod.Status.InitContainerStatuses, "init container status should exist")
				initStatus := pod.Status.InitContainerStatuses[0]
				require.NotNil(t, initStatus.State.Terminated, "init container should have terminated")
				require.Equal(
					t,
					int32(0),
					initStatus.State.Terminated.ExitCode,
					"init container should exit successfully",
				)

				require.NotEmpty(t, pod.Status.ContainerStatuses, "main container status should exist")
				mainStatus := pod.Status.ContainerStatuses[0]
				require.NotNil(t, mainStatus.State.Running, "main container should be running")

				return ctx
			}).
		Assess("ls is allowed in main container",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				t.Log("verifying ls is allowed in main container")

				r := ctx.Value(key("client")).(*resources.Resources)

				var stdout, stderr bytes.Buffer

				err := r.ExecInPod(
					ctx,
					workloadNamespace,
					podName,
					"main-container",
					[]string{"ls", "/"},
					&stdout,
					&stderr,
				)

				require.NoError(t, err, "ls execution in main container should be allowed")
				require.NotEmpty(t, stdout.String(), "ls should produce output")

				return ctx
			}).
		Assess("bash is blocked in main container",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				t.Log("verifying bash is blocked in main container")

				r := ctx.Value(key("client")).(*resources.Resources)

				var stdout, stderr bytes.Buffer

				err := r.ExecInPod(
					ctx,
					workloadNamespace,
					podName,
					"main-container",
					[]string{"bash", "-c", "echo 'bash should be blocked'"},
					&stdout,
					&stderr,
				)

				require.Error(t, err, "bash execution in main container should be blocked")
				require.Empty(t, stdout.String(), "stdout should be empty when bash is blocked")
				require.Contains(t, stderr.String(), "operation not permitted",
					"stderr should contain 'operation not permitted' when bash is blocked")

				return ctx
			}).
		Teardown(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			t.Log("cleaning up test resources")

			r := ctx.Value(key("client")).(*resources.Resources)

			pod := corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      podName,
					Namespace: workloadNamespace,
				},
			}
			err := r.Delete(ctx, &pod)
			require.NoError(t, err, "failed to delete pod")

			err = wait.For(
				conditions.New(r).ResourceDeleted(&pod),
				wait.WithTimeout(DefaultOperationTimeout),
			)
			require.NoError(t, err, "pod was not deleted within timeout")

			policy := v1alpha1.WorkloadPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      policyName,
					Namespace: workloadNamespace,
				},
			}
			err = r.Delete(ctx, &policy)
			require.NoError(t, err, "failed to delete workload policy")

			return ctx
		}).Feature()
}
