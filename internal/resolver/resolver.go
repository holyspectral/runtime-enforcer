package resolver

import (
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/rancher-sandbox/runtime-enforcer/internal/bpf"
	"github.com/rancher-sandbox/runtime-enforcer/internal/types/policymode"
	"k8s.io/client-go/tools/events"
)

// Option is a functional option for configuring a Resolver.
type Option func(*Resolver)

// WithEventRecorder configures an optional Kubernetes event recorder on the Resolver.
// When set, a Warning event is emitted on the Pod whenever a pod references a
// WorkloadPolicy that does not yet exist in the resolver cache.
func WithEventRecorder(recorder events.EventRecorder) Option {
	return func(r *Resolver) {
		r.eventRecorder = recorder
	}
}

type Resolver struct {
	// let's see if we can split this unique lock in multiple locks later
	mu              sync.Mutex
	logger          *slog.Logger
	nriSynchronized atomic.Bool
	// todo!: we should add a cache with deleted pods/containers so that we can resolve also recently deleted ones
	podCache        map[PodID]*podEntry
	cgroupIDToPodID map[CgroupID]PodID

	nextPolicyID                PolicyID
	wpState                     map[NamespacedPolicyName]*wpInfo
	policyUpdateBinariesFunc    func(policyID PolicyID, values []string, op bpf.PolicyValuesOperation) error
	policyModeUpdateFunc        func(policyID PolicyID, mode policymode.Mode, op bpf.PolicyModeOperation) error
	cgTrackerUpdateFunc         func(cgID uint64, cgroupPath string) error
	cgroupToPolicyMapUpdateFunc func(polID PolicyID, cgroupIDs []CgroupID, op bpf.CgroupPolicyOperation) error
	eventRecorder               events.EventRecorder
}

func NewResolver(
	logger *slog.Logger,
	cgTrackerUpdateFunc func(cgID uint64, cgroupPath string) error,
	cgroupToPolicyMapUpdateFunc func(polID PolicyID, cgroupIDs []CgroupID, op bpf.CgroupPolicyOperation) error,
	policyUpdateBinariesFunc func(policyID uint64, values []string, op bpf.PolicyValuesOperation) error,
	policyModeUpdateFunc func(policyID uint64, mode policymode.Mode, op bpf.PolicyModeOperation) error,
	opts ...Option,
) (*Resolver, error) {
	r := &Resolver{
		logger:                      logger.With("component", "resolver"),
		podCache:                    make(map[PodID]*podEntry),
		cgroupIDToPodID:             make(map[CgroupID]PodID),
		cgTrackerUpdateFunc:         cgTrackerUpdateFunc,
		cgroupToPolicyMapUpdateFunc: cgroupToPolicyMapUpdateFunc,
		policyUpdateBinariesFunc:    policyUpdateBinariesFunc,
		policyModeUpdateFunc:        policyModeUpdateFunc,
		wpState:                     make(map[NamespacedPolicyName]*wpInfo),
		nextPolicyID:                PolicyID(1),
	}
	for _, opt := range opts {
		opt(r)
	}
	return r, nil
}
