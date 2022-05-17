/*
Copyright 2018 Gravitational, Inc.

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

package srv

import (
	"context"
	"fmt"
	"time"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/client/proto"
	apidefaults "github.com/gravitational/teleport/api/defaults"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/inventory"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/teleport/lib/utils/interval"

	"github.com/gravitational/trace"
	"github.com/gravitational/trace/trail"
	"github.com/jonboulle/clockwork"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// HeartbeatI abstracts over the basic interfact of Heartbeat and HeartbeatV2. This can be removed
// once we've fully transitioned to HeartbeatV2.
type HeartbeatI interface {
	Run() error
	Close() error
}

// SSHServerHeatbeatConfig configures the HeartbeatV2 for an ssh server.
type SSHServerHeartbeatConfig struct {
	// InventoryHandle is used to send heartbeats.
	InventoryHandle inventory.DownstreamHandle
	// GetServer gets the latest server spec.
	GetServer func() *types.ServerV2
	// Announcer is a fallback used to perform basic upsert-style heartbeats
	// if the control stream is unavailable (optional).
	Announcer auth.Announcer
	// OnHeartbeat is a per-attempt callback (optional).
	OnHeartbeat func(error)
	// AnnounceInterval is the interval at which heartbeats are attempted (optional).
	AnnounceInterval time.Duration
	// PollInterval is the interval at which checks for change are performed (optional).
	PollInterval time.Duration
}

func (c *SSHServerHeartbeatConfig) CheckAndSetDefaults() error {
	if c.InventoryHandle == nil {
		return trace.BadParameter("missing required parameter InventoryHandle for ssh heartbeat")
	}
	if c.GetServer == nil {
		return trace.BadParameter("missing required parameter GetServer for ssh heartbeat")
	}
	if c.AnnounceInterval == 0 {
		// default to 2/3rds of the default server expiry.  since we use the "seventh jitter"
		// for our periodics, that translates to an average interval of ~6m, a slight increase
		// from the average of ~5m30s that was used for V1 ssh server heartbeats.
		c.AnnounceInterval = 2 * (apidefaults.ServerAnnounceTTL / 3)
	}
	if c.PollInterval == 0 {
		c.PollInterval = defaults.HeartbeatCheckPeriod
	}
	return nil
}

func NewSSHServerHeartbeat(cfg SSHServerHeartbeatConfig) (*HeartbeatV2, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	ctx, cancel := context.WithCancel(cfg.InventoryHandle.CloseContext())
	return &HeartbeatV2{
		inner: &sshServerHeartbeatV2{
			getServer: cfg.GetServer,
			announcer: cfg.Announcer,
		},
		onHeartbeatInner: cfg.OnHeartbeat,
		handle:           cfg.InventoryHandle,
		announceInterval: cfg.AnnounceInterval,
		pollInterval:     cfg.PollInterval,
		closeContext:     ctx,
		cancel:           cancel,
	}, nil
}

// HeartbeatV2 heartbeats presence via the inventory control stream.
type HeartbeatV2 struct {
	handle inventory.DownstreamHandle
	inner  heartbeatV2

	announceInterval time.Duration
	pollInterval     time.Duration

	onHeartbeatInner func(error)

	closeContext context.Context
	cancel       context.CancelFunc
}

func (h *HeartbeatV2) run() {
	// note: these errors are never actually displayed, but onHeartbeat expects an error,
	// se we we just allocate something reasonably descriptive once.
	announceFailed := trace.Errorf("control stream heartbeat failed (variant=%T)", h.inner)
	fallbackFailed := trace.Errorf("upsert fallback heartbeat failed (variant=%T)", h.inner)

	// set up interval for forced announcement (i.e. heartbeat even if state is unchanged).
	announce := interval.New(interval.Config{
		FirstDuration: utils.HalfJitter(h.announceInterval),
		Duration:      h.announceInterval,
		Jitter:        utils.NewSeventhJitter(),
	})
	defer announce.Stop()

	// set up interval for polling the inner heartbeat impl for changes.
	poll := interval.New(interval.Config{
		FirstDuration: utils.HalfJitter(h.pollInterval),
		Duration:      h.pollInterval,
		Jitter:        utils.NewSeventhJitter(),
	})
	defer poll.Stop()

	// backoffFallback approximately replicates the ~1m backoff used by heartbeat V1 when an announce
	// failes. This can be removed once we remove the fallback announce operation, since control-stream
	// based heartbeats inherit backoff from the stream handle and don't need special backoff.
	var backoffFallback time.Time

	// shouldAnnounce is set to true if announce interval elapses, or if polling informs us of a change.
	// it stays true until a *successful* announce. the value of this variable is preserved when going
	// between the inner control stream based announce loop and the outer upsert based announce loop.
	// the initial value is false to give the control stream a chance to become available.  the first
	// call to poll always returns true, so we still heartbeat within a few seconds of startup regardless.
	var shouldAnnounce bool

	log.Info("debug -> starting heartbeat loop.")

Outer:
	for {
		if shouldAnnounce && time.Now().After(backoffFallback) {
			log.Info("debug -> performing fallback announce.")
			if ok := h.inner.FallbackAnnounce(h.closeContext); ok {
				// reset announce interval and state on successful announce
				announce.Reset()
				shouldAnnounce = false
				h.onHeartbeat(nil)
			} else {
				// announce failed, enter a backoff state.
				backoffFallback = time.Now().Add(utils.SeventhJitter(time.Minute))
				h.onHeartbeat(fallbackFailed)
			}
		}
		// outer select waits for a sender to become available. until one does, announce/poll
		// events are handled via the FallbackAnnounce method which doesn't rely on having a
		// healthy sender stream.
		select {
		case sender := <-h.handle.Sender():
			log.Info("debug -> control stream sender acquired.")
			// poll immediately when sender becomes available.
			if h.inner.Poll() {
				shouldAnnounce = true
			}
			for {
				if shouldAnnounce {
					log.Info("debug -> performing control stream announce.")
					if ok := h.inner.Announce(h.closeContext, sender); ok {
						// reset announce interval and state on successful announce
						announce.Reset()
						shouldAnnounce = false
						h.onHeartbeat(nil)
					} else {
						h.onHeartbeat(announceFailed)
					}
				}
				// inner select is identical to outer select except that announcements are
				// performed by the primary Announce method, since we have access to the
				// sender within this scope.
				select {
				case <-sender.Done():
					// sender closed, break into the outer loop and wait for a new sender
					// to be available.
					continue Outer
				case <-announce.Next():
					shouldAnnounce = true
				case <-poll.Next():
					if h.inner.Poll() {
						shouldAnnounce = true
					}
				case <-h.closeContext.Done():
					return
				}
			}
		case <-announce.Next():
			shouldAnnounce = true
		case <-poll.Next():
			if h.inner.Poll() {
				shouldAnnounce = true
			}
		case <-h.closeContext.Done():
			return
		}
	}
}

func (h *HeartbeatV2) Run() error {
	log.Info("debug -> starting heartbeat v2 goroutine.")
	h.run()
	return nil
}

func (h *HeartbeatV2) Close() error {
	h.cancel()
	return nil
}

func (h *HeartbeatV2) onHeartbeat(err error) {
	if h.onHeartbeatInner == nil {
		return
	}
	h.onHeartbeatInner(err)
}

// heartbeatV2 is the pluggable core of the HeartbeatV2 type. A service needing to use HeartbeatV2 should
// have a corresponding implementation.
type heartbeatV2 interface {
	// Poll is used to check for changes since last *successful* heartbeat (note: Poll should also
	// return true if no heartbeat has been successfully executed yet).
	Poll() (changed bool)
	// FallbackAnnounce is called if a heartbeat is needed but the inventory control stream is
	// unavailable. In theory this is probably only relevant for cases where the auth has been
	// downgraded to an earlier version than it should have been, but its still preferable to
	// make an effort to heartbeat in that case, so we're including it for now.
	FallbackAnnounce(ctx context.Context) (ok bool)
	// Announce attempts to heartbeat via the inventory control stream.
	Announce(ctx context.Context, sender inventory.DownstreamSender) (ok bool)
}

// sshServerHeartbeatV2 is the heartbeatV2 implementation for ssh servers.
type sshServerHeartbeatV2 struct {
	getServer   func() *types.ServerV2
	announcer   auth.Announcer
	prev        *types.ServerV2
	lastWarning time.Time
}

func (h *sshServerHeartbeatV2) Poll() (changed bool) {
	if h.prev == nil {
		return true
	}
	return services.CompareServers(h.getServer(), h.prev) == services.Different
}

func (h *sshServerHeartbeatV2) FallbackAnnounce(ctx context.Context) (ok bool) {
	if h.announcer == nil {
		return false
	}
	server := h.getServer()
	_, err := h.announcer.UpsertNode(ctx, server)
	if err != nil {
		log.Warnf("Failed to perform fallback heartbeat for ssh server: %v", err)
		return false
	}
	h.prev = server
	return true
}

func (h *sshServerHeartbeatV2) Announce(ctx context.Context, sender inventory.DownstreamSender) (ok bool) {
	server := h.getServer()
	err := sender.Send(ctx, proto.InventoryHeartbeat{
		SSHServer: h.getServer(),
	})
	if err != nil {
		log.Warnf("Failed to perform inventory heartbeat for ssh server: %v", err)
		return false
	}
	h.prev = server
	return true
}

// KeepAliveState represents state of the heartbeat
type KeepAliveState int

func (k KeepAliveState) String() string {
	switch k {
	case HeartbeatStateInit:
		return "init"
	case HeartbeatStateAnnounce:
		return "announce"
	case HeartbeatStateAnnounceWait:
		return "announce-wait"
	case HeartbeatStateKeepAlive:
		return "keepalive"
	case HeartbeatStateKeepAliveWait:
		return "keepalive-wait"
	default:
		return fmt.Sprintf("unknown state %v", int(k))
	}
}

const (
	// HeartbeatStateInit is set when
	// the state has not been collected yet,
	// or the state is not fetched
	HeartbeatStateInit KeepAliveState = iota
	// HeartbeatStateAnnounce is set when full
	// state has to be announced back to the auth server
	HeartbeatStateAnnounce
	// HeartbeatStateAnnounceWait is set after successful
	// announce, heartbeat will wait until server updates
	// information, or time for next announce comes
	HeartbeatStateAnnounceWait
	// HeartbeatStateKeepAlive is set when
	// only sending keep alives is necessary
	HeartbeatStateKeepAlive
	// HeartbeatStateKeepAliveWait is set when
	// heartbeat will waiting until it's time to send keep alive
	HeartbeatStateKeepAliveWait
)

// HeartbeatMode represents the mode of the heartbeat
// node, proxy or auth server
type HeartbeatMode int

// CheckAndSetDefaults checks values and sets defaults
func (h HeartbeatMode) CheckAndSetDefaults() error {
	switch h {
	case HeartbeatModeNode, HeartbeatModeProxy, HeartbeatModeAuth, HeartbeatModeKube, HeartbeatModeApp, HeartbeatModeDB, HeartbeatModeWindowsDesktopService, HeartbeatModeWindowsDesktop:
		return nil
	default:
		return trace.BadParameter("unrecognized mode")
	}
}

// String returns user-friendly representation of the mode
func (h HeartbeatMode) String() string {
	switch h {
	case HeartbeatModeNode:
		return "Node"
	case HeartbeatModeProxy:
		return "Proxy"
	case HeartbeatModeAuth:
		return "Auth"
	case HeartbeatModeKube:
		return "Kube"
	case HeartbeatModeApp:
		return "App"
	case HeartbeatModeDB:
		return "Database"
	case HeartbeatModeWindowsDesktopService:
		return "WindowsDesktopService"
	case HeartbeatModeWindowsDesktop:
		return "WindowsDesktop"
	default:
		return fmt.Sprintf("<unknown: %v>", int(h))
	}
}

const (
	// HeartbeatModeNode sets heartbeat to node
	// updates that support keep alives
	HeartbeatModeNode HeartbeatMode = iota
	// HeartbeatModeProxy sets heartbeat to proxy
	// that does not support keep alives
	HeartbeatModeProxy
	// HeartbeatModeAuth sets heartbeat to auth
	// that does not support keep alives
	HeartbeatModeAuth
	// HeartbeatModeKube is a mode for kubernetes service heartbeats.
	HeartbeatModeKube
	// HeartbeatModeApp sets heartbeat to apps and will use keep alives.
	HeartbeatModeApp
	// HeartbeatModeDB sets heatbeat to db
	HeartbeatModeDB
	// HeartbeatModeWindowsDesktopService sets heatbeat mode to windows desktop
	// service.
	HeartbeatModeWindowsDesktopService
	// HeartbeatModeWindowsDesktop sets heatbeat mode to windows desktop.
	HeartbeatModeWindowsDesktop
)

// NewHeartbeat returns a new instance of heartbeat
func NewHeartbeat(cfg HeartbeatConfig) (*Heartbeat, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	ctx, cancel := context.WithCancel(cfg.Context)
	h := &Heartbeat{
		cancelCtx:       ctx,
		cancel:          cancel,
		HeartbeatConfig: cfg,
		Entry: log.WithFields(log.Fields{
			trace.Component: teleport.Component(cfg.Component, "beat"),
		}),
		checkTicker: cfg.Clock.NewTicker(cfg.CheckPeriod),
		announceC:   make(chan struct{}, 1),
		sendC:       make(chan struct{}, 1),
	}
	h.Debugf("Starting %v heartbeat with announce period: %v, keep-alive period %v, poll period: %v", cfg.Mode, cfg.AnnouncePeriod, cfg.KeepAlivePeriod, cfg.CheckPeriod)
	return h, nil
}

// GetServerInfoFn is function that returns server info
type GetServerInfoFn func() (types.Resource, error)

// HeartbeatConfig is a heartbeat configuration
type HeartbeatConfig struct {
	// Mode sets one of the proxy, auth or node modes.
	Mode HeartbeatMode
	// Context is parent context that signals
	// heartbeat cancel
	Context context.Context
	// Component is a name of component used in logs
	Component string
	// Announcer is used to announce presence
	Announcer auth.Announcer
	// GetServerInfo returns server information
	GetServerInfo GetServerInfoFn
	// ServerTTL is a server TTL used in announcements
	ServerTTL time.Duration
	// KeepAlivePeriod is a period between light-weight
	// keep alive calls, that only update TTLs and don't consume
	// bandwidh, also is used to derive time between
	// failed attempts as well for auth and proxy modes
	KeepAlivePeriod time.Duration
	// AnnouncePeriod is a period between announce calls,
	// when client sends full server specification
	// to the presence service
	AnnouncePeriod time.Duration
	// CheckPeriod is a period to check for updates
	CheckPeriod time.Duration
	// Clock is a clock used to override time in tests
	Clock clockwork.Clock
	// OnHeartbeat is called after every heartbeat. A non-nil error is passed
	// when a heartbeat fails.
	OnHeartbeat func(error)
}

// CheckAndSetDefaults checks and sets default values
func (cfg *HeartbeatConfig) CheckAndSetDefaults() error {
	if err := cfg.Mode.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}
	if cfg.Context == nil {
		return trace.BadParameter("missing parameter Context")
	}
	if cfg.Announcer == nil {
		return trace.BadParameter("missing parameter Announcer")
	}
	if cfg.Component == "" {
		return trace.BadParameter("missing parameter Component")
	}
	if cfg.CheckPeriod == 0 {
		return trace.BadParameter("missing parameter CheckPeriod")
	}
	if cfg.KeepAlivePeriod == 0 {
		return trace.BadParameter("missing parameter KeepAlivePeriod")
	}
	if cfg.AnnouncePeriod == 0 {
		return trace.BadParameter("missing parameter AnnouncePeriod")
	}
	if cfg.ServerTTL == 0 {
		return trace.BadParameter("missing parmeter ServerTTL")
	}
	if cfg.GetServerInfo == nil {
		return trace.BadParameter("missing parameter GetServerInfo")
	}
	if cfg.Clock == nil {
		cfg.Clock = clockwork.NewRealClock()
	}
	if cfg.OnHeartbeat == nil {
		// Blackhole callback if none was specified.
		cfg.OnHeartbeat = func(error) {}
	}

	return nil
}

// Heartbeat keeps heartbeat state, it is implemented
// according to actor model - all interactions with it are to be done
// with signals
type Heartbeat struct {
	HeartbeatConfig
	cancelCtx context.Context
	cancel    context.CancelFunc
	*log.Entry
	state     KeepAliveState
	current   types.Resource
	keepAlive *types.KeepAlive
	// nextAnnounce holds time of the next scheduled announce attempt
	nextAnnounce time.Time
	// nextKeepAlive holds the time of the nex scheduled keep alive attempt
	nextKeepAlive time.Time
	// checkTicker is a ticker for state transitions
	// during which different checks are performed
	checkTicker clockwork.Ticker
	// keepAliver sends keep alive updates
	keepAliver types.KeepAliver
	// announceC is event receives an event
	// whenever new announce has been sent, used in tests
	announceC chan struct{}
	// sendC is event channel used to trigger
	// new announces
	sendC chan struct{}
}

// Run periodically calls to announce presence,
// should be called explicitly in a separate goroutine
func (h *Heartbeat) Run() error {
	defer func() {
		h.reset(HeartbeatStateInit)
		h.checkTicker.Stop()
	}()
	for {
		err := h.fetchAndAnnounce()
		if err != nil {
			h.Warningf("Heartbeat failed %v.", err)
		}
		h.OnHeartbeat(err)
		select {
		case <-h.checkTicker.Chan():
		case <-h.sendC:
			h.Debugf("Asked check out of cycle")
		case <-h.cancelCtx.Done():
			h.Debugf("Heartbeat exited.")
			return nil
		}
	}
}

// Close closes all timers and goroutines,
// note that this function is equivalent of cancelling
// of the context passed in configuration and can be
// used interchangeably
func (h *Heartbeat) Close() error {
	// note that close does not clean up resources,
	// because it is unaware of heartbeat actual state,
	// Run() could may as well be creating new keep aliver
	// while this function attempts to close it,
	// so instead it relies on Run() loop to clean up after itself
	h.cancel()
	return nil
}

// setState is used to debug state transitions
// as it logs in addition to setting state
func (h *Heartbeat) setState(state KeepAliveState) {
	h.state = state
}

// reset resets keep alive state
// and sends the state back to the initial state
// of sending full update
func (h *Heartbeat) reset(state KeepAliveState) {
	h.setState(state)
	h.nextAnnounce = time.Time{}
	h.nextKeepAlive = time.Time{}
	h.keepAlive = nil
	if h.keepAliver != nil {
		if err := h.keepAliver.Close(); err != nil {
			h.Warningf("Failed to close keep aliver: %v", err)
		}
		h.keepAliver = nil
	}
}

// fetch, if succeeded updates or sets current server
// to the last received server
func (h *Heartbeat) fetch() error {
	// failed to fetch server info?
	// reset to init state regardless of the current state
	server, err := h.GetServerInfo()
	if err != nil {
		h.reset(HeartbeatStateInit)
		return trace.Wrap(err)
	}
	switch h.state {
	// in case of successful state fetch, move to announce from init
	case HeartbeatStateInit:
		h.current = server
		h.reset(HeartbeatStateAnnounce)
		return nil
		// nothing to do in announce state
	case HeartbeatStateAnnounce:
		return nil
	case HeartbeatStateAnnounceWait:
		// time to announce
		if h.Clock.Now().UTC().After(h.nextAnnounce) {
			h.current = server
			h.reset(HeartbeatStateAnnounce)
			return nil
		}
		result := services.CompareServers(h.current, server)
		// server update happened, time to announce
		if result == services.Different {
			h.current = server
			h.reset(HeartbeatStateAnnounce)
		}
		return nil
		// nothing to do in keep alive state
	case HeartbeatStateKeepAlive:
		return nil
		// Stay in keep alive state in case
		// if there are no changes
	case HeartbeatStateKeepAliveWait:
		// time to send a new keep alive
		if h.Clock.Now().UTC().After(h.nextKeepAlive) {
			h.setState(HeartbeatStateKeepAlive)
			return nil
		}
		result := services.CompareServers(h.current, server)
		// server update happened, move to announce
		if result == services.Different {
			h.current = server
			h.reset(HeartbeatStateAnnounce)
		}
		return nil
	default:
		return trace.BadParameter("unsupported state: %v", h.state)
	}
}

func (h *Heartbeat) announce() error {
	switch h.state {
	// nothing to do in those states in terms of announce
	case HeartbeatStateInit, HeartbeatStateKeepAliveWait, HeartbeatStateAnnounceWait:
		return nil
	case HeartbeatStateAnnounce:
		// proxies and auth servers don't support keep alive logic yet,
		// so keep state at announce forever for proxies
		switch h.Mode {
		case HeartbeatModeProxy:
			proxy, ok := h.current.(types.Server)
			if !ok {
				return trace.BadParameter("expected services.Server, got %#v", h.current)
			}
			err := h.Announcer.UpsertProxy(proxy)
			if err != nil {
				// try next announce using keep alive period,
				// that happens more frequently
				h.nextAnnounce = h.Clock.Now().UTC().Add(h.KeepAlivePeriod)
				h.setState(HeartbeatStateAnnounceWait)
				return trace.Wrap(err)
			}
			h.nextAnnounce = h.Clock.Now().UTC().Add(h.AnnouncePeriod)
			h.notifySend()
			h.setState(HeartbeatStateAnnounceWait)
			return nil
		case HeartbeatModeAuth:
			auth, ok := h.current.(types.Server)
			if !ok {
				return trace.BadParameter("expected services.Server, got %#v", h.current)
			}
			err := h.Announcer.UpsertAuthServer(auth)
			if err != nil {
				h.nextAnnounce = h.Clock.Now().UTC().Add(h.KeepAlivePeriod)
				h.setState(HeartbeatStateAnnounceWait)
				return trace.Wrap(err)
			}
			h.nextAnnounce = h.Clock.Now().UTC().Add(h.AnnouncePeriod)
			h.notifySend()
			h.setState(HeartbeatStateAnnounceWait)
			return nil
		case HeartbeatModeNode:
			node, ok := h.current.(types.Server)
			if !ok {
				return trace.BadParameter("expected services.Server, got %#v", h.current)
			}
			keepAlive, err := h.Announcer.UpsertNode(h.cancelCtx, node)
			if err != nil {
				return trace.Wrap(err)
			}
			h.notifySend()
			keepAliver, err := h.Announcer.NewKeepAliver(h.cancelCtx)
			if err != nil {
				h.reset(HeartbeatStateInit)
				return trace.Wrap(err)
			}
			h.nextAnnounce = h.Clock.Now().UTC().Add(h.AnnouncePeriod)
			h.nextKeepAlive = h.Clock.Now().UTC().Add(h.KeepAlivePeriod)
			h.keepAlive = keepAlive
			h.keepAliver = keepAliver
			h.setState(HeartbeatStateKeepAliveWait)
			return nil
		case HeartbeatModeKube:
			kube, ok := h.current.(types.Server)
			if !ok {
				return trace.BadParameter("expected services.Server, got %#v", h.current)
			}
			keepAlive, err := h.Announcer.UpsertKubeServiceV2(h.cancelCtx, kube)
			if err != nil {
				// Check if the error is an Unimplemented grpc status code,
				// if it is fall back to old keepalive method
				// DELETE in 11.0
				if e, ok := status.FromError(trail.ToGRPC(err)); ok && e.Code() == codes.Unimplemented {
					err := h.Announcer.UpsertKubeService(h.cancelCtx, kube)
					if err != nil {
						h.nextAnnounce = h.Clock.Now().UTC().Add(h.KeepAlivePeriod)
						h.setState(HeartbeatStateAnnounceWait)
						return trace.Wrap(err)
					}
					h.nextAnnounce = h.Clock.Now().UTC().Add(h.AnnouncePeriod)
					h.notifySend()
					h.setState(HeartbeatStateAnnounceWait)
					return nil
				}
				return trace.Wrap(err)
			}
			h.notifySend()
			keepAliver, err := h.Announcer.NewKeepAliver(h.cancelCtx)
			if err != nil {
				h.reset(HeartbeatStateInit)
				return trace.Wrap(err)
			}
			h.nextAnnounce = h.Clock.Now().UTC().Add(h.AnnouncePeriod)
			h.nextKeepAlive = h.Clock.Now().UTC().Add(h.KeepAlivePeriod)
			h.keepAlive = keepAlive
			h.keepAliver = keepAliver
			h.setState(HeartbeatStateKeepAliveWait)
			return nil
		case HeartbeatModeApp:
			var keepAlive *types.KeepAlive
			var err error
			switch current := h.current.(type) {
			case types.Server:
				keepAlive, err = h.Announcer.UpsertAppServer(h.cancelCtx, current)
			case types.AppServer:
				keepAlive, err = h.Announcer.UpsertApplicationServer(h.cancelCtx, current)
			default:
				return trace.BadParameter("expected types.AppServer, got %#v", h.current)
			}
			if err != nil {
				return trace.Wrap(err)
			}
			h.notifySend()
			keepAliver, err := h.Announcer.NewKeepAliver(h.cancelCtx)
			if err != nil {
				h.reset(HeartbeatStateInit)
				return trace.Wrap(err)
			}
			h.nextAnnounce = h.Clock.Now().UTC().Add(h.AnnouncePeriod)
			h.nextKeepAlive = h.Clock.Now().UTC().Add(h.KeepAlivePeriod)
			h.keepAlive = keepAlive
			h.keepAliver = keepAliver
			h.setState(HeartbeatStateKeepAliveWait)
			return nil
		case HeartbeatModeDB:
			db, ok := h.current.(types.DatabaseServer)
			if !ok {
				return trace.BadParameter("expected services.DatabaseServer, got %#v", h.current)
			}
			keepAlive, err := h.Announcer.UpsertDatabaseServer(h.cancelCtx, db)
			if err != nil {
				return trace.Wrap(err)
			}
			h.notifySend()
			keepAliver, err := h.Announcer.NewKeepAliver(h.cancelCtx)
			if err != nil {
				h.reset(HeartbeatStateInit)
				return trace.Wrap(err)
			}
			h.nextAnnounce = h.Clock.Now().UTC().Add(h.AnnouncePeriod)
			h.nextKeepAlive = h.Clock.Now().UTC().Add(h.KeepAlivePeriod)
			h.keepAlive = keepAlive
			h.keepAliver = keepAliver
			h.setState(HeartbeatStateKeepAliveWait)
			return nil
		case HeartbeatModeWindowsDesktopService:
			wd, ok := h.current.(types.WindowsDesktopService)
			if !ok {
				return trace.BadParameter("expected services.WindowsDesktopService, got %#v", h.current)
			}
			keepAlive, err := h.Announcer.UpsertWindowsDesktopService(h.cancelCtx, wd)
			if err != nil {
				return trace.Wrap(err)
			}
			h.notifySend()
			keepAliver, err := h.Announcer.NewKeepAliver(h.cancelCtx)
			if err != nil {
				h.reset(HeartbeatStateInit)
				return trace.Wrap(err)
			}
			h.nextAnnounce = h.Clock.Now().UTC().Add(h.AnnouncePeriod)
			h.nextKeepAlive = h.Clock.Now().UTC().Add(h.KeepAlivePeriod)
			h.keepAlive = keepAlive
			h.keepAliver = keepAliver
			h.setState(HeartbeatStateKeepAliveWait)
			return nil
		case HeartbeatModeWindowsDesktop:
			desktop, ok := h.current.(types.WindowsDesktop)
			if !ok {
				return trace.BadParameter("expected types.WindowsDesktop, got %#v", h.current)
			}
			err := h.Announcer.CreateWindowsDesktop(h.cancelCtx, desktop)
			if trace.IsAlreadyExists(err) {
				err = h.Announcer.UpdateWindowsDesktop(h.cancelCtx, desktop)
			}
			if err != nil {
				h.nextAnnounce = h.Clock.Now().UTC().Add(h.KeepAlivePeriod)
				h.setState(HeartbeatStateAnnounceWait)
				return trace.Wrap(err)
			}
			h.nextAnnounce = h.Clock.Now().UTC().Add(h.AnnouncePeriod)
			h.notifySend()
			h.setState(HeartbeatStateAnnounceWait)
			return nil
		default:
			return trace.BadParameter("unknown mode %q", h.Mode)
		}
	case HeartbeatStateKeepAlive:
		keepAlive := *h.keepAlive
		keepAlive.Expires = h.Clock.Now().UTC().Add(h.ServerTTL)
		timeout := time.NewTimer(h.KeepAlivePeriod)
		defer timeout.Stop()
		select {
		case <-h.cancelCtx.Done():
			return nil
		case <-timeout.C:
			h.Warningf("Blocked on keep alive send, going to reset.")
			h.reset(HeartbeatStateInit)
			return trace.ConnectionProblem(nil, "timeout sending keep alive")
		case h.keepAliver.KeepAlives() <- keepAlive:
			h.notifySend()
			h.nextKeepAlive = h.Clock.Now().UTC().Add(h.KeepAlivePeriod)
			h.setState(HeartbeatStateKeepAliveWait)
			return nil
		case <-h.keepAliver.Done():
			h.Warningf("Keep alive has failed: %v.", h.keepAliver.Error())
			err := h.keepAliver.Error()
			h.reset(HeartbeatStateInit)
			return trace.ConnectionProblem(err, "keep alive channel closed")
		}
	default:
		return trace.BadParameter("unsupported state: %v", h.state)
	}
}

func (h *Heartbeat) notifySend() {
	select {
	case h.announceC <- struct{}{}:
		return
	default:
	}
}

// fetchAndAnnounce fetches data about server
// and announces it to the server
func (h *Heartbeat) fetchAndAnnounce() error {
	if err := h.fetch(); err != nil {
		return trace.Wrap(err)
	}
	if err := h.announce(); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// ForceSend forces send cycle, used in tests, returns
// nil in case of success, error otherwise
func (h *Heartbeat) ForceSend(timeout time.Duration) error {
	timeoutC := time.After(timeout)
	select {
	case h.sendC <- struct{}{}:
	case <-timeoutC:
		return trace.ConnectionProblem(nil, "timeout waiting for send")
	}
	select {
	case <-h.announceC:
		return nil
	case <-timeoutC:
		return trace.ConnectionProblem(nil, "timeout waiting for announce to be sent")
	}
}
