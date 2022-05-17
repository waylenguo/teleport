/*
Copyright 2022 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package inventory

import (
	"context"
	"time"

	"github.com/gravitational/teleport/api/client"
	"github.com/gravitational/teleport/api/client/proto"
	apidefaults "github.com/gravitational/teleport/api/defaults"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/teleport/lib/utils/interval"
	"github.com/gravitational/trace"
	"github.com/siddontang/go/log"
)

// Auth is an interface representing the subset of the auth API that must be made available
// to the controller in order for it to be able to handle control streams.
type Auth interface {
	UpsertNode(context.Context, types.Server) (*types.KeepAlive, error)
	KeepAliveServer(context.Context, types.KeepAlive) error
}

// Controller manages the inventory control streams registered with a given auth instance. Incoming
// messages are processed by invoking the appropriate methods on the Auth interface.
type Controller struct {
	store           *Store
	auth            Auth
	serverKeepAlive time.Duration
	serverTTL       time.Duration
	closeContext    context.Context
	cancel          context.CancelFunc
}

func NewController(auth Auth) *Controller {
	ctx, cancel := context.WithCancel(context.Background())
	baseKeepAlive := apidefaults.ServerKeepAliveTTL()
	return &Controller{
		store: NewStore(),
		// use 1.5x standard server keep alive since we use a jitter that
		// shortens the actual average interval.
		serverKeepAlive: baseKeepAlive + (baseKeepAlive / 2),
		serverTTL:       apidefaults.ServerAnnounceTTL,
		auth:            auth,
		closeContext:    ctx,
		cancel:          cancel,
	}
}

// RegisterControlStream registers a new control stream with the controller.
func (c *Controller) RegisterControlStream(stream client.UpstreamInventoryControlStream, hello proto.UpstreamInventoryHello) {
	handle := newUpstreamHandle(stream, hello)
	c.store.Insert(handle)
	go c.handleControlStream(handle)
}

// GetControlStream gets a control stream for the given server ID if one exists (if multiple control streams
// exist one is selected pseudorandomly).
func (c *Controller) GetControlStream(serverID string) (handle UpstreamHandle, ok bool) {
	handle, ok = c.store.Get(serverID)
	return
}

// Iter iterates across all handles registered with this controller.
// note: if multiple handles are registered for a given server, only
// one handle is selected pseudorandomly to be observed.
func (c *Controller) Iter(fn func(UpstreamHandle)) {
	c.store.Iter(fn)
}

func (c *Controller) handleControlStream(handle *upstreamHandle) {
	defer func() {
		c.store.Remove(handle)
		handle.Close(trace.Errorf("control stream handler exiting")) // safe to double-close
	}()
	keepAliveInterval := interval.New(interval.Config{
		Duration:      c.serverKeepAlive,
		FirstDuration: utils.HalfJitter(c.serverKeepAlive),
		Jitter:        utils.NewSeventhJitter(),
	})
	defer keepAliveInterval.Stop()
	for {
		select {
		case msg := <-handle.Recv():
			switch m := msg.(type) {
			case proto.UpstreamInventoryHello:
				log.Warnf("Unexpected upstream hello on control stream of server %q.", handle.Hello().ServerID)
				handle.Close(trace.BadParameter("unexpected upstream hello"))
				return
			case proto.InventoryHeartbeat:
				if err := c.handleHeartbeat(handle, m); err != nil {
					handle.Close(err)
					return
				}
			case proto.UpstreamInventoryPong:
				c.handlePong(handle, m)
			default:
				log.Warnf("Unexpected upstream message type %T on control stream of server %q.", m, handle.Hello().ServerID)
				handle.Close(trace.BadParameter("unexpected upstream message type %T", m))
				return
			}
		case <-keepAliveInterval.Next():
			if err := c.handleKeepAlive(handle); err != nil {
				handle.Close(err)
				return
			}
		case req := <-handle.pingC:
			log.Infof("debug -> pulled ping request")
			// pings require multiplexing, so we need to do the sending from this
			// goroutine rather than sending directly via the handle.
			if err := c.handlePingRequest(handle, req); err != nil {
				handle.Close(err)
				return
			}
		case <-handle.Done():
			return
		case <-c.closeContext.Done():
			handle.Close(trace.Errorf("inventory controller closing"))
			return
		}
	}
}

func (c *Controller) handlePong(handle *upstreamHandle, msg proto.UpstreamInventoryPong) {
	pending, ok := handle.pings[msg.ID]
	if !ok {
		log.Warnf("Unexpected upstream pong from server %q (id=%d).", handle.Hello().ServerID, msg.ID)
		return
	}
	pending.rspC <- pingResponse{
		d: time.Since(pending.start),
	}
	delete(handle.pings, msg.ID)
}

func (c *Controller) handlePingRequest(handle *upstreamHandle, req pingRequest) error {
	handle.pingCounter++
	ping := proto.DownstreamInventoryPing{
		ID: handle.pingCounter,
	}
	start := time.Now()
	if err := handle.Send(c.closeContext, ping); err != nil {
		req.rspC <- pingResponse{
			err: err,
		}
		return trace.Wrap(err)
	}
	handle.pings[handle.pingCounter] = pendingPing{
		start: start,
		rspC:  req.rspC,
	}
	log.Infof("debug -> ping request sent do downstream server")
	return nil
}

func (c *Controller) handleHeartbeat(handle *upstreamHandle, hb proto.InventoryHeartbeat) error {
	if hb.SSHServer != nil {
		log.Infof("debug -> handling incoming control stream heartbeat for ssh server.")
		// the auth layer verifies that a stream's hello message matches the identity and capabilities of the
		// client cert. after that point it is our responsibility to ensure that heartbeated information is
		// consistent with the identity and capabilities claimed in the initial hello.
		if !handle.HasService(types.RoleNode) {
			return trace.AccessDenied("control stream not configured to support ssh server heartbeats")
		}
		if hb.SSHServer.GetName() != handle.Hello().ServerID {
			return trace.AccessDenied("incorrect ssh server ID (expected %q, got %q)", handle.Hello().ServerID, hb.SSHServer.GetName())
		}

		hb.SSHServer.SetExpiry(time.Now().Add(c.serverTTL).UTC())

		lease, err := c.auth.UpsertNode(c.closeContext, hb.SSHServer)
		if err != nil {
			// TODO(fspmarshall): we should cache the most recent heartbeat and retry instead
			// of returning an error here.  We don't want flaky backend connectivity to result
			// in a thundering herd issue.
			return trace.Errorf("failed to upsert ssh server on heartbeat: %v", err)
		}
		handle.sshServerLease = lease
	}
	return nil
}

func (c *Controller) handleKeepAlive(handle *upstreamHandle) error {
	if handle.sshServerLease != nil {
		lease := *handle.sshServerLease
		lease.Expires = time.Now().Add(c.serverTTL).UTC()
		if err := c.auth.KeepAliveServer(c.closeContext, lease); err != nil {
			// TODO(fspmarshall): this should probably not terminate the stream.
			return trace.Errorf("failed to keep alive ssh server: %v", err)
		}
	}
	return nil
}

func (c *Controller) Close() {
	c.cancel()
}
