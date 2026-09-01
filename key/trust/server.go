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
// names one; the delegated key sets, if it names any; the wrapped key server;
// and last the records a domain publishes for itself, if the configuration
// asks for discovery. Nothing found further down, nor a cache in front of it,
// can shadow a pinned record.
//
// A configuration that names no key server answers for its own user from
// itself, after the pinned directory and before the sets. See self.
//
// The key server comes before discovery because it is named in the
// configuration, deliberately and for a reason its owner had, where discovery
// is a standing willingness to ask any domain about its own users. Discovery
// then answers for the users the key server does not know, which includes
// every user when the configuration names no key server at all.
//
// An answer from the wrapped key server that carries an attestation is checked
// against the pinned trust anchors, and the attested record used in its place.
// A key server that attests to what it serves therefore need not be trusted.
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
			if err := s.checkStale(u); err != nil {
				return nil, errors.E(op, err)
			}
			return u, nil
		case errors.Is(errors.NotExist, err):
			// Not pinned; try the sources below.
		default:
			// Present but unusable; see above.
			return nil, errors.E(op, err)
		}
	}
	if u := s.self(name); u != nil {
		return u, nil
	}
	if s.sets != nil {
		if u := s.sets.lookup(s.dd.config, s.dd.dir, name); u != nil {
			return u, nil
		}
	}
	if err := s.dial(); err != nil {
		// The configuration may name no key server that can be
		// reached at all, which is not fatal while discovery may
		// still answer.
		if u := s.discover(name); u != nil {
			return u, nil
		}
		return nil, errors.E(op, err)
	}
	u, err := s.dd.dialed.Lookup(name)
	if err != nil {
		if u := s.discover(name); u != nil {
			return u, nil
		}
		// The key server's error is the one to report: it is the
		// source the configuration named, and discovery answers
		// silently or not at all by design.
		return nil, errors.E(op, err)
	}
	if err := s.checkAttestation(u); err != nil {
		// The server offered a signature that does not hold. That is
		// hostile rather than an absence, so do not go on to ask
		// somewhere else; say so.
		return nil, errors.E(op, err)
	}
	return u, nil
}

// self returns the record the configuration describes for its own user, or
// nil if name is some other user or the configuration cannot describe it.
//
// It answers only when the configuration names no key server. Everything the
// record holds is in the configuration already: the user name, the two
// endpoints, and the public half of the factotum's key pair. A configuration
// that pins the users it talks to should not also have to pin itself in order
// to name itself, which it must do to reach its own tree at all.
// key/usercache does the same for its own user, but sits between a key
// server and its caller and so is absent from a configuration that has no key
// server: this is that same answer, given where it is still needed.
//
// It comes after the pinned directory, which is a deliberate act, and before
// the delegated sets. Before the sets and not after because reading a set is
// an Upspin read, which authenticates, which needs this same key: a server
// whose own user is not pinned would go to the network to learn a key it is
// holding, and where the set lives in a tree that server serves, it would call
// itself to do it. That is not merely wasteful. The inner request runs while
// the outer one holds the tree it was loading, and the two wait on each other.
//
// It is confined to the unassigned transport so that a configuration that does
// name a key server still asks it, which is what lets "upspin user" report a
// configuration that disagrees with the record the server holds.
func (s *server) self(name upspin.UserName) *upspin.User {
	if s.dd.endpoint.Transport != upspin.Unassigned {
		return nil
	}
	cfg := s.dd.config
	if cfg == nil || name != cfg.UserName() {
		return nil
	}
	f := cfg.Factotum()
	if f == nil {
		// No key to report; a config with secrets=none.
		return nil
	}
	return &upspin.User{
		Name:      name,
		Dirs:      []upspin.Endpoint{cfg.DirEndpoint()},
		Stores:    []upspin.Endpoint{cfg.StoreEndpoint()},
		PublicKey: f.PublicKey(),
	}
}

// discover returns what the user's own domain publishes for name, or nil if
// the configuration does not ask for discovery or the domain publishes nothing
// that can be accepted.
func (s *server) discover(name upspin.UserName) *upspin.User {
	if s.discovery == nil {
		return nil
	}
	return s.discovery.lookup(s.dd.config, s.dd.dir, name)
}

// checkAttestation inspects the attestation on a record from the wrapped key
// server. A key server is otherwise an unconditionally trusted party: it can
// return any key for any user, and the client will wrap the keys of the files
// it shares to whatever it is given. An attestation removes that trust for the
// records that carry one, since it is made by a key the reader pinned as the
// anchor for the user's domain, not by the server.
//
// A record whose attestation verifies replaces the one the server sent, so
// that only signed fields are used. A record with no attestation, or one for a
// domain with no anchor pinned, is left as it is: it is no more and no less
// believable than a key server's answer has always been. A record offered with
// a signature that does not hold is refused outright; nothing honest produces
// one.
func (s *server) checkAttestation(u *upspin.User) error {
	if s.dd.dir == "" || len(u.Attestation) == 0 {
		return nil
	}
	attested, err := Accept(s.dd.dir, u.Attestation)
	if err != nil {
		if errors.Is(errors.NotExist, err) {
			// No anchor pinned for this domain, so there is
			// nothing to check the signature against.
			return nil
		}
		return errors.E(u.Name, errors.Errorf(
			"the key server offered an attestation that does not verify: %v", err))
	}
	if attested.Name != u.Name {
		return errors.E(u.Name, errors.Invalid, errors.Errorf(
			"the key server offered an attestation for %s", attested.Name))
	}
	*u = *attested
	return nil
}

// checkStale reports an error if a pinned record disagrees with one that has
// already been found for the same user in a delegated key set or by discovery.
// Such a record is attested by the trust anchor the reader pinned for the
// user's domain, so it says the key has changed since the record was pinned;
// nothing else could produce it.
//
// This matters because nothing in Upspin pushes a key change. A peer holding a
// record from before a rotation will wrap the keys of the files it shares to a
// key its owner no longer holds, and neither of them will be told: the loss of
// access appears later, as a file that cannot be read. Refusing to answer with
// a pinned record that is known to be superseded turns that silence into a
// message.
//
// Only records already in hand are consulted, so this costs nothing and finds
// nothing that has not been fetched for some other reason. Use the -check flag
// of the keytrust subcommand to look deliberately.
func (s *server) checkStale(pinned *upspin.User) error {
	for _, published := range []*upspin.User{
		peek(s.sets, pinned.Name),
		peekDiscovery(s.discovery, pinned.Name),
	} {
		if published == nil || published.PublicKey == pinned.PublicKey {
			continue
		}
		return errors.E(errors.Invalid, pinned.Name, errors.Str(
			"the pinned key is not the key now published for this user and attested by "+
				"the trust anchor for their domain: the pinned record is out of date. "+
				"Check it with 'upspin keytrust -check' and replace it."))
	}
	return nil
}

// peek returns what a delegated key set has already been found to publish for
// name, tolerating a nil set.
func peek(s *sets, name upspin.UserName) *upspin.User {
	if s == nil {
		return nil
	}
	return s.peek(name)
}

// peekDiscovery returns what discovery has already found for name, tolerating
// a nil discovery.
func peekDiscovery(d *discovery, name upspin.UserName) *upspin.User {
	if d == nil {
		return nil
	}
	return d.peek(name)
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
