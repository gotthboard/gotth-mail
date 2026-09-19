package plugin

import (
	"context"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/version"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type Seam string

const (
	Webmail      Seam = "webmail"
	DNS          Seam = "dns"
	ACME         Seam = "acme"
	Backup       Seam = "backup"
	Notification Seam = "notification"
	Import       Seam = "import"
)

const (
	MetadataCorrelationID = "x-gotth-mail-correlation-id"
	MetadataServiceToken  = "x-gotth-mail-service-token"
)

type Registration struct {
	Name         string
	Seam         Seam
	Endpoint     string
	Enabled      bool
	ServiceToken string
	Capabilities []string
	SecretSlots  []string
	Foundation   *FoundationBinding
}
type Registry struct{ Plugins map[string]Registration }
type Request struct {
	CorrelationID, ServiceToken string
	Deadline                    time.Time // internal/direct-call helper only; gRPC uses context deadline/metadata.
}
type HealthResponse struct {
	Healthy bool
	Message string
}
type VersionResponse struct{ Name, Version string }
type CapabilitiesResponse struct{ Capabilities []string }

func (r Registry) auth(ctx context.Context, name string, req Request) (Registration, error) {
	if _, ok := ctx.Deadline(); !ok {
		if req.Deadline.IsZero() {
			return Registration{}, status.Error(codes.InvalidArgument, "deadline required")
		}
		if time.Now().After(req.Deadline) {
			return Registration{}, status.Error(codes.DeadlineExceeded, "deadline exceeded")
		}
	}
	if err := ctx.Err(); err != nil {
		return Registration{}, status.Error(codes.DeadlineExceeded, "deadline exceeded")
	}
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if req.CorrelationID == "" {
			req.CorrelationID = first(md.Get(MetadataCorrelationID))
		}
		if req.ServiceToken == "" {
			req.ServiceToken = first(md.Get(MetadataServiceToken))
		}
	}
	if req.CorrelationID == "" {
		return Registration{}, status.Error(codes.InvalidArgument, "correlation id metadata required")
	}
	p, ok := r.Plugins[name]
	if !ok {
		return Registration{}, status.Error(codes.NotFound, "plugin not found")
	}
	if req.ServiceToken == "" {
		return Registration{}, status.Error(codes.Unauthenticated, "service identity metadata required")
	}
	if !p.Enabled {
		return Registration{}, status.Error(codes.PermissionDenied, "plugin disabled")
	}
	if req.ServiceToken != p.ServiceToken {
		return Registration{}, status.Error(codes.Unauthenticated, "invalid service identity")
	}
	return p, nil
}
func first(v []string) string {
	if len(v) == 0 {
		return ""
	}
	return v[0]
}
func (r Registry) Health(ctx context.Context, name string, req Request) (HealthResponse, error) {
	_, err := r.auth(ctx, name, req)
	if err != nil {
		return HealthResponse{}, err
	}
	return HealthResponse{true, "ok"}, nil
}
func (r Registry) Version(ctx context.Context, name string, req Request) (VersionResponse, error) {
	p, err := r.auth(ctx, name, req)
	if err != nil {
		return VersionResponse{}, err
	}
	return VersionResponse{p.Name, version.Version}, nil
}
func (r Registry) Capabilities(ctx context.Context, name string, req Request) (CapabilitiesResponse, error) {
	p, err := r.auth(ctx, name, req)
	if err != nil {
		return CapabilitiesResponse{}, err
	}
	if len(p.Capabilities) == 0 {
		return CapabilitiesResponse{}, status.Error(codes.Internal, "malformed capability response")
	}
	return CapabilitiesResponse{p.Capabilities}, nil
}
