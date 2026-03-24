package e2e_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
	"sigs.k8s.io/e2e-framework/pkg/types"
)

func getEnforcementOnNewPodsTest() types.Feature {
	workloadNamespace := envconf.RandomName("enforce-namespace", 32)

	return features.New("enforcement on new pods").
		Setup(SetupSharedK8sClient).
		Setup(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			createTestNamespace(ctx, t, workloadNamespace)
			return ctx
		}).
		Assess("required resources become available", IfRequiredResourcesAreCreated).
		Assess("a namespace-scoped policy can be enforced correctly",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				r := ctx.Value(key("client")).(*resources.Resources)

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

				// 1. Create the resource and wait for it to be deployed.
				createAndWaitWP(ctx, t, policy.DeepCopy())
				// 2. Deploy test pods
				createAndWaitUbuntuDeployment(ctx, t, workloadNamespace, withPolicy("test-policy"))

				// 3. Run command in the pod and verify the result.
				podName, err := findPodByPrefix(ctx, workloadNamespace, "ubuntu-deployment")
				require.NoError(t, err)

				expectedResults := []struct {
					Commands []string
					Allowed  bool
				}{
					{
						Commands: []string{"/usr/bin/ls"},
						Allowed:  true,
					},
					{
						Commands: []string{"/usr/bin/apt", "update"},
						Allowed:  false,
					},
				}

				for _, expectedResult := range expectedResults {
					var stdout, stderr bytes.Buffer

					t.Log("running:", expectedResult.Commands)
					err = r.ExecInPod(
						ctx,
						workloadNamespace,
						podName,
						"ubuntu",
						expectedResult.Commands,
						&stdout,
						&stderr,
					)

					if expectedResult.Allowed {
						require.NoError(t, err)
					} else {
						require.Error(t, err)
						require.Empty(t, stdout.String())
						require.Contains(t, stderr.String(), "operation not permitted\n")
					}
				}

				// 4. Delete test Deployment
				deleteUbuntuDeployment(ctx, t, workloadNamespace)

				// 5. Delete WorkloadPolicy and wait for it to be gone.
				deleteAndWaitWP(ctx, t, &policy)
				return ctx
			}).Feature()
}
