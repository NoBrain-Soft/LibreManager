package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/nobrain-soft/libremanager/internal/agent/osutil"
	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
)

// ContainerSocket is a Docker-compatible API socket.
type ContainerSocket struct {
	// Runtime is "docker" or "podman".
	Runtime string
	// Path is the socket path (absolute host path; joined below Root).
	Path string
}

// defaultContainerSockets are probed in order; a runtime is queried once.
var defaultContainerSockets = []ContainerSocket{
	{"docker", "/run/docker.sock"},
	{"docker", "/var/run/docker.sock"},
	{"podman", "/run/podman/podman.sock"},
}

const (
	containerAPITimeout = 5 * time.Second
	maxContainerJSON    = 8 << 20
)

// Containers returns the Containers section. It queries the Docker / Podman
// API (GET /containers/json?all=1) over the unix socket only when the agent
// may connect to it; the agent user is normally not in the docker group, in
// which case the section is empty. No Docker SDK is used.
func (c *Collector) Containers(ctx context.Context) (*agentv1.InventorySection, error) {
	sockets := c.ContainerSockets
	if sockets == nil {
		sockets = defaultContainerSockets
	}
	var out []*agentv1.Container
	done := map[string]bool{}
	for _, s := range sockets {
		if done[s.Runtime] {
			continue
		}
		list, err := queryContainers(ctx, c.path(s.Path), s.Runtime)
		if err != nil {
			if !errors.Is(err, syscall.ENOENT) && !errors.Is(err, syscall.EACCES) && !errors.Is(err, syscall.ECONNREFUSED) {
				c.log().Debug("container API query failed", "runtime", s.Runtime, "socket", s.Path, "error", err)
			}
			continue
		}
		done[s.Runtime] = true
		out = append(out, list...)
		if len(out) >= maxContainers {
			out = out[:maxContainers]
			break
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].GetRuntime() != out[j].GetRuntime() {
			return out[i].GetRuntime() < out[j].GetRuntime()
		}
		return out[i].GetName() < out[j].GetName()
	})
	cs := &agentv1.Containers{}
	cs.Containers, _ = capBySize(out, budgetContainers)
	return newSection(cs)
}

type apiContainer struct {
	ID    string   `json:"Id"`
	Names []string `json:"Names"`
	Image string   `json:"Image"`
	State string   `json:"State"`
}

func queryContainers(ctx context.Context, socket, runtime string) ([]*agentv1.Container, error) {
	if len(socket) > 107 {
		return nil, fmt.Errorf("socket path too long: %s", filepath.Base(socket))
	}
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
		DisableKeepAlives:      true,
		ResponseHeaderTimeout:  containerAPITimeout,
		MaxResponseHeaderBytes: 64 << 10,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: containerAPITimeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/containers/json?all=1", nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("query %s: %w", runtime, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("query %s: HTTP %d", runtime, resp.StatusCode)
	}
	var list []apiContainer
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxContainerJSON)).Decode(&list); err != nil {
		return nil, fmt.Errorf("decode %s containers: %w", runtime, err)
	}
	out := make([]*agentv1.Container, 0, min(len(list), maxContainers))
	for _, ct := range list {
		if len(out) >= maxContainers {
			break
		}
		name := ""
		if len(ct.Names) > 0 {
			name = strings.TrimPrefix(ct.Names[0], "/")
		}
		id := ct.ID
		if len(id) > 64 {
			id = id[:64]
		}
		out = append(out, &agentv1.Container{
			Runtime: runtime,
			Id:      osutil.Clean(id, maxShort),
			Name:    osutil.Clean(name, maxName),
			Image:   osutil.Clean(ct.Image, maxName),
			State:   osutil.Clean(ct.State, maxShort),
		})
	}
	return out, nil
}
