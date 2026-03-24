package e2e_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
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

func getPromotionTest() types.Feature {
	workloadNamespace := envconf.RandomName("main-namespace", 32)

	return features.New("Promotion").
		Setup(SetupSharedK8sClient).
		Setup(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			createTestNamespace(ctx, t, workloadNamespace)
			return ctx
		}).
		Setup(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			createAndWaitUbuntuDeployment(ctx, t, workloadNamespace)
			return ctx
		}).
		Assess("required resources become available", IfRequiredResourcesAreCreated).
		Assess("the workload proposal is created successfully for the ubuntu pod",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				r := ctx.Value(key("client")).(*resources.Resources)

				proposal := v1alpha1.WorkloadPolicyProposal{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "deploy-ubuntu-deployment",
						Namespace: workloadNamespace, // to be consistent with test data.
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
				r := ctx.Value(key("client")).(*resources.Resources)

				t.Log("waiting for policy proposal to be created: ", id)

				proposal := v1alpha1.WorkloadPolicyProposal{
					ObjectMeta: metav1.ObjectMeta{
						Name:      id,
						Namespace: workloadNamespace, // to be consistent with test data.
					},
				}

				// There are two categories of processes to be learned:
				// 1. /usr/bin/bash: the container entrypoint.
				// 2. /usr/bin/sleep & /usr/bin/ls: the commands the container executes
				t.Log("waiting for processes to be learned")

				err := wait.For(conditions.New(r).ResourceMatch(
					&proposal,
					func(_ k8s.Object) bool {
						rules, ok := proposal.Spec.RulesByContainer["ubuntu"]

						if !ok {
							return false
						}

						return verifyUbuntuLearnedProcesses(rules.Executables.Allowed)
					}),
					wait.WithTimeout(DefaultOperationTimeout),
				)
				require.NoError(t, err)

				return context.WithValue(ctx, key("proposal"), &proposal)
			}).
		Assess("a proposal is promoted to a policy through labeling and the workloadPolicy is created",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				t.Log("create a policy")

				r := ctx.Value(key("client")).(*resources.Resources)
				proposal := ctx.Value(key("proposal")).(*v1alpha1.WorkloadPolicyProposal)

				t.Log("applying the label to the policy proposal: ", proposal.Name, v1alpha1.ApprovalLabelKey)

				labels := proposal.GetLabels()
				if labels == nil {
					labels = map[string]string{}
				}

				labels[v1alpha1.ApprovalLabelKey] = "true"

				proposal.SetLabels(labels)
				err := r.Update(ctx, proposal)
				require.NoError(t, err)

				t.Log("waiting for the policy to be created: ", proposal.Name)

				policy := v1alpha1.WorkloadPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      proposal.ObjectMeta.Name,
						Namespace: proposal.ObjectMeta.Namespace,
					},
					Spec: v1alpha1.WorkloadPolicySpec{
						Mode: "monitor",
						RulesByContainer: map[string]*v1alpha1.WorkloadPolicyRules{
							"ubuntu": {
								Executables: v1alpha1.WorkloadPolicyExecutables{
									Allowed: proposal.Spec.RulesByContainer["ubuntu"].Executables.Allowed,
								},
							},
						},
					},
				}

				err = wait.For(conditions.New(r).ResourceMatch(&policy, func(_ k8s.Object) bool {
					return true
				}), wait.WithTimeout(DefaultOperationTimeout))
				require.NoError(t, err)

				return context.WithValue(ctx, key("policy"), &policy)
			}).
		Assess("pod exec will not be blocked since the policy is in monitoring mode",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				r := ctx.Value(key("client")).(*resources.Resources)

				podName, err := findPodByPrefix(ctx, workloadNamespace, "ubuntu-deployment")
				require.NoError(t, err)

				var stdout, stderr bytes.Buffer

				err = r.ExecInPod(ctx, workloadNamespace, podName, "ubuntu", []string{"mkdir"}, &stdout, &stderr)
				require.Error(t, err)
				require.Empty(t, stdout.String())
				require.Equal(t, "mkdir: missing operand\nTry 'mkdir --help' for more information.\n", stderr.String())

				return ctx
			}).
		Assess("delete policy", func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			r := ctx.Value(key("client")).(*resources.Resources)
			policy := ctx.Value(key("policy")).(*v1alpha1.WorkloadPolicy)
			proposal := ctx.Value(key("proposal")).(*v1alpha1.WorkloadPolicyProposal)

			err := r.Delete(ctx, proposal)
			require.NoError(t, err)

			err = r.Delete(ctx, policy)
			require.NoError(t, err)

			return ctx
		}).
		Teardown(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			deleteUbuntuDeployment(ctx, t, workloadNamespace)
			return ctx
		}).Feature()
}
