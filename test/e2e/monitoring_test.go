package e2e_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/runtime-enforcer/internal/types/policymode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
	"sigs.k8s.io/e2e-framework/pkg/types"
)

func getMonitoringTest() types.Feature {
	return features.New("Monitoring").
		Setup(SetupSharedK8sClient).
		Setup(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			workloadNamespace := envconf.RandomName("monitoring-namespace", 32)
			createTestNamespace(ctx, t, workloadNamespace)
			return context.WithValue(ctx, key("namespace"), workloadNamespace)
		}).
		Setup(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			namespace := ctx.Value(key("namespace")).(string)

			policy := &v1alpha1.WorkloadPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: namespace,
				},
				Spec: v1alpha1.WorkloadPolicySpec{
					Mode: "monitor",
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

			createAndWaitWP(ctx, t, policy.DeepCopy())
			return context.WithValue(ctx, key("policy"), policy.DeepCopy())
		}).
		Setup(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			namespace := ctx.Value(key("namespace")).(string)
			createAndWaitUbuntuDeployment(ctx, t, namespace, withPolicy("test-policy"))
			ubuntuPodName, err := findPodByPrefix(ctx, namespace, "ubuntu-deployment")
			require.NoError(t, err)
			require.NotEmpty(t, ubuntuPodName)
			return context.WithValue(ctx, key("targetPodName"), ubuntuPodName)
		}).
		Assess("required resources become available", IfRequiredResourcesAreCreated).
		Assess("a namespace-scoped policy can monitor behaviors correctly",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				namespace := ctx.Value(key("namespace")).(string)
				expectedPodName := ctx.Value(key("targetPodName")).(string)
				r := ctx.Value(key("client")).(*resources.Resources)

				t.Log("executing allowed command (should not produce violations)")
				var stdout, stderr bytes.Buffer
				err := r.ExecInPod(ctx, namespace, expectedPodName, "ubuntu",
					[]string{"/usr/bin/ls"}, &stdout, &stderr)
				require.NoError(t, err)

				t.Log("executing disallowed command to trigger violation")
				stdout.Reset()
				stderr.Reset()
				err = r.ExecInPod(ctx, namespace, expectedPodName, "ubuntu",
					[]string{"/usr/bin/sh", "-c", "/usr/bin/apt update"}, &stdout, &stderr)
				require.NoError(t, err)

				t.Log("waiting for violations to appear in WorkloadPolicy status")
				policyToCheck := &v1alpha1.WorkloadPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-policy",
						Namespace: namespace,
					},
				}
				err = wait.For(conditions.New(r).ResourceMatch(policyToCheck, func(obj k8s.Object) bool {
					wp, ok := obj.(*v1alpha1.WorkloadPolicy)
					if !ok {
						return false
					}
					if len(wp.Status.Violations) == 0 {
						return false
					}
					for _, v := range wp.Status.Violations {
						if v.ExecutablePath == "/usr/bin/apt" &&
							v.Action == policymode.MonitorString &&
							v.PodName == expectedPodName {
							return true
						}
					}
					return false
				}), wait.WithTimeout(DefaultOperationTimeout))
				require.NoError(t, err, "violation for /usr/bin/apt should appear in WorkloadPolicy status")

				t.Log("verifying violation record details")
				err = r.Get(ctx, "test-policy", namespace, policyToCheck)
				require.NoError(t, err)
				require.NotEmpty(t, policyToCheck.Status.Violations)

				var found bool
				for _, v := range policyToCheck.Status.Violations {
					if v.ExecutablePath == "/usr/bin/apt" {
						assert.Equal(t, policymode.MonitorString, v.Action)
						assert.Equal(t, expectedPodName, v.PodName)
						found = true
						break
					}
				}
				assert.True(t, found, "should find violation record for /usr/bin/apt")
				return ctx
			}).
		Teardown(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			namespace := ctx.Value(key("namespace")).(string)
			deleteUbuntuDeployment(ctx, t, namespace)

			policy := ctx.Value(key("policy")).(*v1alpha1.WorkloadPolicy)
			deleteAndWaitWP(ctx, t, policy)
			return ctx
		}).Feature()
}
