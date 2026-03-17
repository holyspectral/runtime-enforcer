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

func TestRunPolicyExecAllow(t *testing.T) {
	t.Parallel()

	ns := "test"
	name := "test-policy"

	policy := &apiv1alpha1.WorkloadPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
		},
		Spec: apiv1alpha1.WorkloadPolicySpec{
			RulesByContainer: map[string]*apiv1alpha1.WorkloadPolicyRules{
				"app": {
					Executables: apiv1alpha1.WorkloadPolicyExecutables{
						Allowed: []string{"/bin/ls"},
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
			DryRun:    false,
		},
		PolicyName:  name,
		Executables: []string{"/bin/mv", "/bin/cat"},
		Action:      policyExecActionAllow,
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultOperationTimeout)
	defer cancel()

	err := runPolicyExec(ctx, securityClient, opts, &out)
	require.NoError(t, err)

	updatedPolicy, err := securityClient.WorkloadPolicies(ns).Get(ctx, name, metav1.GetOptions{})
	require.NoError(t, err)

	rules := updatedPolicy.Spec.RulesByContainer["app"]
	require.NotNil(t, rules)
	require.ElementsMatch(t, []string{"/bin/ls", "/bin/mv", "/bin/cat"}, rules.Executables.Allowed)
}

func TestRunPolicyExecDeny(t *testing.T) {
	t.Parallel()

	ns := "test"
	name := "test-policy"

	policy := &apiv1alpha1.WorkloadPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
		},
		Spec: apiv1alpha1.WorkloadPolicySpec{
			RulesByContainer: map[string]*apiv1alpha1.WorkloadPolicyRules{
				"app": {
					Executables: apiv1alpha1.WorkloadPolicyExecutables{
						Allowed: []string{"/bin/ls", "/bin/mv", "/bin/cat"},
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
			DryRun:    false,
		},
		PolicyName:  name,
		Executables: []string{"/bin/mv"},
		Action:      policyExecActionDeny,
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultOperationTimeout)
	defer cancel()

	err := runPolicyExec(ctx, securityClient, opts, &out)
	require.NoError(t, err)

	updatedPolicy, err := securityClient.WorkloadPolicies(ns).Get(ctx, name, metav1.GetOptions{})
	require.NoError(t, err)

	rules := updatedPolicy.Spec.RulesByContainer["app"]
	require.NotNil(t, rules)
	require.ElementsMatch(t, []string{"/bin/ls", "/bin/cat"}, rules.Executables.Allowed)
}

func TestRunPolicyExecDryRun(t *testing.T) {
	t.Parallel()

	ns := "test"
	name := "test-policy"

	policy := &apiv1alpha1.WorkloadPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
		},
		Spec: apiv1alpha1.WorkloadPolicySpec{
			RulesByContainer: map[string]*apiv1alpha1.WorkloadPolicyRules{
				"app": {
					Executables: apiv1alpha1.WorkloadPolicyExecutables{
						Allowed: []string{"/bin/ls"},
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
			DryRun:    true,
		},
		PolicyName:  name,
		Executables: []string{"/bin/mv", "/bin/cat"},
		Action:      policyExecActionAllow,
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultOperationTimeout)
	defer cancel()

	err := runPolicyExec(ctx, securityClient, opts, &out)
	require.NoError(t, err)

	// original policy should remain unchanged
	unchangedPolicy, err := securityClient.WorkloadPolicies(ns).Get(ctx, name, metav1.GetOptions{})
	require.NoError(t, err)
	rules := unchangedPolicy.Spec.RulesByContainer["app"]
	require.NotNil(t, rules)
	require.ElementsMatch(t, []string{"/bin/ls"}, rules.Executables.Allowed)

	output := out.String()
	require.Contains(
		t,
		output,
		"Would allow executables [/bin/mv /bin/cat] for WorkloadPolicy \"test-policy\" in namespace \"test\".",
	)
}
