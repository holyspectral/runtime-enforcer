package grpcexporter

import (
	"context"

	"log/slog"

	"github.com/rancher-sandbox/runtime-enforcer/internal/resolver"
	pb "github.com/rancher-sandbox/runtime-enforcer/proto/agent/v1"
)

// agentObserver implements the AgentObserver gRPC server.
type agentObserver struct {
	pb.UnimplementedAgentObserverServer

	logger   *slog.Logger
	resolver *resolver.Resolver
}

func newAgentObserver(logger *slog.Logger, resolver *resolver.Resolver) *agentObserver {
	return &agentObserver{
		logger:   logger.With("component", "agent_observer"),
		resolver: resolver,
	}
}

// ListPoliciesStatus list policies inside the resolver and returns their status.
func (s *agentObserver) ListPoliciesStatus(
	ctx context.Context,
	_ *pb.ListPoliciesStatusRequest,
) (*pb.ListPoliciesStatusResponse, error) {
	out := &pb.ListPoliciesStatusResponse{
		Policies: make(map[string]*pb.PolicyStatus),
	}

	statuses := s.resolver.GetPolicyStatuses()
	for policyName, ps := range statuses {
		out.Policies[policyName] = &pb.PolicyStatus{
			State:   ps.State,
			Mode:    ps.Mode,
			Message: ps.Message,
		}
	}

	s.logger.DebugContext(ctx, "listed tracing policies", "count", len(out.GetPolicies()))
	return out, nil
}
