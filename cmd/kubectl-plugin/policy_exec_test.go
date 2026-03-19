package main

import (
	"bytes"
	"context"
	"testing"

	apiv1alpha1 "github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	fakeclient "github.com/rancher-sandbox/runtime-enforcer/pkg/generated/clientset/versioned/fake"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestRunPolicyExec(t *testing.T) {
	t.Parallel()

	const (
		ns   = "test"
		name = "test-policy"
	)

	tests := []struct {
		name         string
		action       policyExecAction
		dryRun       bool
		initialList  []string
		executables  []string
		expectedList []string
		expectMsgSub string
	}{
		{
			name:         "allow_add_multiple",
			action:       policyExecActionAllow,
			dryRun:       false,
			initialList:  []string{"/bin/ls"},
			executables:  []string{"/bin/mv", "/bin/cat"},
			expectedList: []string{"/bin/ls", "/bin/mv", "/bin/cat"},
			expectMsgSub: "Successfully updated executables",
		},
		{
			name:         "deny_remove_one",
			action:       policyExecActionDeny,
			dryRun:       false,
			initialList:  []string{"/bin/ls", "/bin/mv", "/bin/cat"},
			executables:  []string{"/bin/mv"},
			expectedList: []string{"/bin/ls", "/bin/cat"},
			expectMsgSub: "Successfully updated executables",
		},
		{
			name:         "allow_dry_run",
			action:       policyExecActionAllow,
			dryRun:       true,
			initialList:  []string{"/bin/ls"},
			executables:  []string{"/bin/mv", "/bin/cat"},
			expectedList: []string{"/bin/ls", "/bin/mv", "/bin/cat"},
			expectMsgSub: "Would allow executables for WorkloadPolicy",
		},
		{
			name:         "deny_dry_run",
			action:       policyExecActionDeny,
			dryRun:       true,
			initialList:  []string{"/bin/ls", "/bin/mv", "/bin/cat"},
			executables:  []string{"/bin/mv"},
			expectedList: []string{"/bin/ls", "/bin/cat"},
			expectMsgSub: "Would deny executables for WorkloadPolicy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			policy := &apiv1alpha1.WorkloadPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: ns,
				},
				Spec: apiv1alpha1.WorkloadPolicySpec{
					RulesByContainer: map[string]*apiv1alpha1.WorkloadPolicyRules{
						"app": {
							Executables: apiv1alpha1.WorkloadPolicyExecutables{
								Allowed: append([]string(nil), tt.initialList...),
							},
						},
					},
				},
			}

			clientset := fakeclient.NewClientset(policy)
			securityClient := clientset.SecurityV1alpha1()

			var out bytes.Buffer
			opts := &policyExecOptions{
				commonOptions: commonOptions{
					Namespace: ns,
					DryRun:    tt.dryRun,
				},
				PolicyName:  name,
				Executables: tt.executables,
				Action:      tt.action,
			}

			ctx, cancel := context.WithTimeout(context.Background(), defaultOperationTimeout)
			defer cancel()

			err := runPolicyExec(ctx, securityClient, opts, &out)
			require.NoError(t, err)

			output := out.String()
			require.Contains(t, output, tt.expectMsgSub)

			updatedPolicy, err := securityClient.WorkloadPolicies(ns).Get(ctx, name, metav1.GetOptions{})
			require.NoError(t, err)

			rules := updatedPolicy.Spec.RulesByContainer["app"]
			require.NotNil(t, rules)
			require.ElementsMatch(t, tt.expectedList, rules.Executables.Allowed)
		})
	}
}

func TestApplyExecutablesToPolicy_WithContainerFilter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		action         policyExecAction
		containerNames []string
		executables    []string
		initialByKey   map[string][]string
		wantByKey      map[string][]string
		wantChanged    bool
		wantErr        bool
	}{
		{
			name:           "allow_subset_two_containers",
			action:         policyExecActionAllow,
			containerNames: []string{"a,b"},
			executables:    []string{"/bin/mv"},
			initialByKey: map[string][]string{
				"a": []string{"/bin/ls"},
				"b": []string{"/bin/ls"},
				"c": []string{"/bin/ls"},
			},
			wantByKey: map[string][]string{
				"a": []string{"/bin/ls", "/bin/mv"},
				"b": []string{"/bin/ls", "/bin/mv"},
				"c": []string{"/bin/ls"},
			},
			wantChanged: true,
		},
		{
			name:           "deny_subset_one_container",
			action:         policyExecActionDeny,
			containerNames: []string{"b"},
			executables:    []string{"/bin/mv"},
			initialByKey: map[string][]string{
				"a": []string{"/bin/ls", "/bin/mv"},
				"b": []string{"/bin/ls", "/bin/mv"},
				"c": []string{"/bin/ls", "/bin/mv"},
			},
			wantByKey: map[string][]string{
				"a": []string{"/bin/ls", "/bin/mv"},
				"b": []string{"/bin/ls"},
				"c": []string{"/bin/ls", "/bin/mv"},
			},
			wantChanged: true,
		},
		{
			name:           "container_not_found_in_policy",
			action:         policyExecActionAllow,
			containerNames: []string{"missing"},
			executables:    []string{"/bin/mv"},
			initialByKey: map[string][]string{
				"a": []string{"/bin/ls"},
				"b": []string{"/bin/ls"},
			},
			wantErr:     true,
			wantChanged: false,
		},
		{
			name:           "no_container_flag_applies_all",
			action:         policyExecActionDeny,
			containerNames: nil,
			executables:    []string{"/bin/mv"},
			initialByKey: map[string][]string{
				"a": []string{"/bin/ls", "/bin/mv"},
				"b": []string{"/bin/ls", "/bin/mv"},
				"c": []string{"/bin/ls"},
			},
			wantByKey: map[string][]string{
				"a": []string{"/bin/ls"},
				"b": []string{"/bin/ls"},
				"c": []string{"/bin/ls"},
			},
			wantChanged: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rulesByContainer := map[string]*apiv1alpha1.WorkloadPolicyRules{}
			for container, initialAllowed := range tt.initialByKey {
				rulesByContainer[container] = &apiv1alpha1.WorkloadPolicyRules{
					Executables: apiv1alpha1.WorkloadPolicyExecutables{
						Allowed: append([]string(nil), initialAllowed...),
					},
				}
			}

			opts := &policyExecOptions{
				Action:         tt.action,
				Executables:    tt.executables,
				ContainerNames: tt.containerNames,
			}

			changed, err := applyExecutablesToPolicy(rulesByContainer, opts)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.wantChanged, changed)

			for containerName, wantAllowed := range tt.wantByKey {
				rules := rulesByContainer[containerName]
				require.NotNil(t, rules)
				require.ElementsMatch(t, wantAllowed, rules.Executables.Allowed)
			}
		})
	}
}
