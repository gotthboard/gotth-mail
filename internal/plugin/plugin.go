package plugin

import (
	"context"
	"errors"
	"time"
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

type Registration struct {
	Name         string
	Seam         Seam
	Endpoint     string
	Enabled      bool
	ServiceToken string
	Capabilities []string
}
type Registry struct{ Plugins map[string]Registration }
type Request struct {
	CorrelationID, ServiceToken string
	Deadline                    time.Time
}
type HealthResponse struct {
	Healthy bool
	Message string
}
type VersionResponse struct{ Name, Version string }
type CapabilitiesResponse struct{ Capabilities []string }

func (r Registry) auth(name string, req Request) (Registration, error) {
	p, ok := r.Plugins[name]
	if !ok {
		return Registration{}, errors.New("not found")
	}
	if req.ServiceToken == "" {
		return Registration{}, errors.New("UNAUTHENTICATED")
	}
	if !p.Enabled {
		return Registration{}, errors.New("PERMISSION_DENIED")
	}
	if req.ServiceToken != p.ServiceToken {
		return Registration{}, errors.New("UNAUTHENTICATED")
	}
	if !req.Deadline.IsZero() && time.Now().After(req.Deadline) {
		return Registration{}, errors.New("DEADLINE_EXCEEDED")
	}
	return p, nil
}
func (r Registry) Health(ctx context.Context, name string, req Request) (HealthResponse, error) {
	_, err := r.auth(name, req)
	if err != nil {
		return HealthResponse{}, err
	}
	return HealthResponse{true, "ok"}, nil
}
func (r Registry) Version(ctx context.Context, name string, req Request) (VersionResponse, error) {
	p, err := r.auth(name, req)
	if err != nil {
		return VersionResponse{}, err
	}
	return VersionResponse{p.Name, "v0"}, nil
}
func (r Registry) Capabilities(ctx context.Context, name string, req Request) (CapabilitiesResponse, error) {
	p, err := r.auth(name, req)
	if err != nil {
		return CapabilitiesResponse{}, err
	}
	if len(p.Capabilities) == 0 {
		return CapabilitiesResponse{}, errors.New("malformed capability response")
	}
	return CapabilitiesResponse{p.Capabilities}, nil
}
