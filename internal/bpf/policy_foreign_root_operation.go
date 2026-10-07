package bpf

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
)

type PolicyForeignRootOperation uint8

const (
	_ PolicyForeignRootOperation = iota
	UpdateForeignRoot
	DeleteForeignRoot
)

func (m *Manager) updatePolicyForeignRoot(policyID uint64, allow bool) error {
	var value uint8
	if allow {
		value = 1
	}
	if err := m.objs.PolicyAllowForeignRootMap.Update(&policyID, value, ebpf.UpdateAny); err != nil {
		return fmt.Errorf(
			"failed to update policy (id=%d) in map %s with allowForeignRootExec=%t: %w",
			policyID,
			m.objs.PolicyAllowForeignRootMap.String(),
			allow,
			err,
		)
	}
	return nil
}

func (m *Manager) deletePolicyForeignRoot(policyID uint64) error {
	if err := m.objs.PolicyAllowForeignRootMap.Delete(&policyID); err != nil &&
		!errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf(
			"failed to delete policy (id=%d) from map %s: %w",
			policyID,
			m.objs.PolicyAllowForeignRootMap.String(),
			err,
		)
	}
	return nil
}

func (m *Manager) GetPolicyForeignRootUpdateFunc() func(policyID uint64, allow bool, op PolicyForeignRootOperation) error {
	return func(policyID uint64, allow bool, op PolicyForeignRootOperation) error {
		switch op {
		case UpdateForeignRoot:
			return m.handleErrOnShutdown(m.updatePolicyForeignRoot(policyID, allow))
		case DeleteForeignRoot:
			return m.handleErrOnShutdown(m.deletePolicyForeignRoot(policyID))
		default:
			panic("unhandled policy foreign root operation")
		}
	}
}
