// Copyright 2026 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package trust

import (
	"sync"

	"upspin.io/errors"
	"upspin.io/upspin"
)

// server is a KeyServer that answers from the pinned key directory before
// consulting the KeyServer it wraps.
type server struct {
	// base is the wrapped KeyServer, not yet dialed.
	base upspin.KeyServer

	dd *deferredDial
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

// Wrap returns a KeyServer that answers Lookup from the pinned key directory
// named by the configuration passed to Dial, and consults s for users that are
// not pinned.
//
// It must be the outermost wrapper. In particular it must enclose, not be
// enclosed by, key/usercache, so that a cached answer from a key server can
// never shadow a pinned record.
func Wrap(s upspin.KeyServer) upspin.KeyServer {
	return &server{base: s, dd: &deferredDial{}}
}

// Lookup implements upspin.KeyServer. It first looks for a pinned record in
// the key directory, if the configuration names one, and returns that record
// if it is there. Only if the user is not pinned does it ask the wrapped key
// server. A pinned record that is present but unusable is an error: the
// lookup does not fall through to the key server, since that would let a
// damaged or tampered record be replaced silently by whatever the key server
// chose to return.
func (s *server) Lookup(name upspin.UserName) (*upspin.User, error) {
	const op errors.Op = "key/trust.Lookup"
	if s.dd.dir != "" {
		u, err := Read(s.dd.dir, name)
		switch {
		case err == nil:
			return u, nil
		case errors.Is(errors.NotExist, err):
			// Not pinned; ask the wrapped server below.
		default:
			// Present but unusable; see above.
			return nil, errors.E(op, err)
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
	c := *s
	c.dd = &deferredDial{
		config:   cfg,
		endpoint: e,
		dir:      dir,
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
