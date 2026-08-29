// Copyright 2026 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package trust

import (
	"sync"

	"upspin.io/errors"
	"upspin.io/upspin"
)

// server is a KeyServer that answers from the pinned key directory, then from
// the delegated key sets, before consulting the KeyServer it wraps.
type server struct {
	// base is the wrapped KeyServer, not yet dialed.
	base upspin.KeyServer

	dd *deferredDial

	// sets holds the delegated key sets, or is nil if the configuration
	// names none.
	sets *sets

	// discovery holds what has been found by asking domains directly, or
	// is nil if the configuration does not ask for that.
	discovery *discovery
}

// deferredDial defers dialing the wrapped service until a request needs it, so
// that a configuration whose users are all pinned never contacts a key server
// at all. It mirrors the same mechanism in key/usercache.
type deferredDial struct {
	mu       sync.Mutex
	config   upspin.Config
	endpoint upspin.Endpoint
	dir      string // pinned key directory; empty if the config names none.
	dialed   upspin.KeyServer
}

var _ upspin.KeyServer = (*server)(nil)

// Wrap returns a KeyServer that answers Lookup from the pinned key directory,
// the delegated key sets, and the records domains publish for themselves, as
// the configuration passed to Dial asks, and consults s for users found in
// none of them.
//
// It must be the outermost wrapper. In particular it must enclose, not be
// enclosed by, key/usercache, so that a cached answer from a key server can
// never shadow a pinned record.
func Wrap(s upspin.KeyServer) upspin.KeyServer {
	return &server{base: s, dd: &deferredDial{}}
}

// Lookup implements upspin.KeyServer. It consults four sources in turn and
// returns the first answer: the pinned key directory, if the configuration
// names one; the delegated key sets, if it names any; the records a domain
// publishes for itself, if the configuration asks for discovery; and last the
// wrapped key server. The order is the order of authority, so that nothing
// found further down, nor a cache in front of it, can shadow a pinned record.
//
// A pinned record that is present but unusable is an error: the lookup does
// not fall through, since that would let a damaged or tampered record be
// replaced silently by whatever a key server chose to return.
func (s *server) Lookup(name upspin.UserName) (*upspin.User, error) {
	const op errors.Op = "key/trust.Lookup"
	if s.dd.dir != "" {
		u, err := Read(s.dd.dir, name)
		switch {
		case err == nil:
			return u, nil
		case errors.Is(errors.NotExist, err):
			// Not pinned; try the sources below.
		default:
			// Present but unusable; see above.
			return nil, errors.E(op, err)
		}
	}
	if s.sets != nil {
		if u := s.sets.lookup(s.dd.config, s.dd.dir, name); u != nil {
			return u, nil
		}
	}
	if s.discovery != nil {
		if u := s.discovery.lookup(s.dd.config, s.dd.dir, name); u != nil {
			return u, nil
		}
	}
	if err := s.dial(); err != nil {
		return nil, errors.E(op, err)
	}
	u, err := s.dd.dialed.Lookup(name)
	if err != nil {
		return nil, errors.E(op, err)
	}
	return u, nil
}

// Put implements upspin.KeyServer. Pinning is a local operation, performed by
// the keytrust subcommand of the upspin command; Put always addresses the
// wrapped key server.
func (s *server) Put(user *upspin.User) error {
	const op errors.Op = "key/trust.Put"
	if err := s.dial(); err != nil {
		return errors.E(op, err)
	}
	if err := s.dd.dialed.Put(user); err != nil {
		return errors.E(op, err)
	}
	return nil
}

// Dial implements upspin.Dialer.
func (s *server) Dial(cfg upspin.Config, e upspin.Endpoint) (upspin.Service, error) {
	const op errors.Op = "key/trust.Dial"
	dir, err := Dir(cfg)
	if err != nil {
		return nil, errors.E(op, err)
	}
	paths, err := Sets(cfg)
	if err != nil {
		return nil, errors.E(op, err)
	}
	c := *s
	c.dd = &deferredDial{
		config:   cfg,
		endpoint: e,
		dir:      dir,
	}
	c.sets = nil
	if len(paths) > 0 {
		c.sets = &sets{paths: paths}
	}
	c.discovery = nil
	if Discovery(cfg) {
		c.discovery = &discovery{}
	}
	return &c, nil
}

// Endpoint implements upspin.Service.
func (s *server) Endpoint() upspin.Endpoint {
	// Do not let Endpoint trigger a Dial.
	s.dd.mu.Lock()
	svc := s.dd.dialed
	s.dd.mu.Unlock()
	if svc != nil {
		return svc.Endpoint()
	}
	return s.base.Endpoint()
}

// Authenticate implements upspin.Service.
func (s *server) Authenticate(upspin.Config) error {
	return errors.Str("key/trust.Authenticate: not implemented")
}

// Close implements upspin.Service.
func (s *server) Close() {
	s.dd.mu.Lock()
	svc := s.dd.dialed
	s.dd.mu.Unlock()
	if svc != nil {
		svc.Close()
		return
	}
	s.base.Close()
}

// dial dials the wrapped key server, using the arguments given to Dial. It is
// a no-op if that has already happened.
func (s *server) dial() error {
	s.dd.mu.Lock()
	defer s.dd.mu.Unlock()

	if s.dd.dialed != nil {
		return nil
	}
	if s.dd.config == nil {
		return errors.Str("server not dialed")
	}
	svc, err := s.base.Dial(s.dd.config, s.dd.endpoint)
	if err != nil {
		return err
	}
	s.dd.dialed = svc.(upspin.KeyServer)
	return nil
}
