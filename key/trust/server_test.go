// Copyright 2026 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package trust

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"upspin.io/config"
	"upspin.io/errors"
	"upspin.io/upspin"
)

// fakeKey is a KeyServer that records whether it was dialed and answers for a
// fixed set of users.
type fakeKey struct {
	dialed *bool
	users  map[upspin.UserName]*upspin.User
}

func (f *fakeKey) Lookup(name upspin.UserName) (*upspin.User, error) {
	if u, ok := f.users[name]; ok {
		return u, nil
	}
	return nil, errors.E(errors.NotExist, name)
}

func (f *fakeKey) Put(u *upspin.User) error {
	f.users[u.Name] = u
	return nil
}

func (f *fakeKey) Dial(upspin.Config, upspin.Endpoint) (upspin.Service, error) {
	*f.dialed = true
	return f, nil
}

func (f *fakeKey) Endpoint() upspin.Endpoint        { return upspin.Endpoint{Transport: upspin.InProcess} }
func (f *fakeKey) Close()                           {}
func (f *fakeKey) Authenticate(upspin.Config) error { return nil }

// dial returns a dialed trust server over dir, plus a flag reporting whether
// the wrapped server has been dialed.
func dial(t *testing.T, dir string, base map[upspin.UserName]*upspin.User) (upspin.KeyServer, *bool) {
	t.Helper()
	dialed := new(bool)
	cfg := config.SetUserName(config.New(), "ann@example.com")
	if dir != "" {
		cfg = config.SetValue(cfg, ConfigKey, dir)
	}
	svc, err := Wrap(&fakeKey{dialed: dialed, users: base}).Dial(cfg, upspin.Endpoint{Transport: upspin.InProcess})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	return svc.(upspin.KeyServer), dialed
}

func TestPinnedRecordWins(t *testing.T) {
	dir := t.TempDir()
	pinned := annUser()
	if err := Write(dir, pinned); err != nil {
		t.Fatal(err)
	}

	// The wrapped server holds a different key for the same user: exactly
	// the substitution that pinning exists to prevent.
	impostor := annUser()
	impostor.PublicKey = bobKey

	ks, dialed := dial(t, dir, map[upspin.UserName]*upspin.User{"ann@example.com": impostor})

	got, err := ks.Lookup("ann@example.com")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got.PublicKey != annKey {
		t.Errorf("Lookup returned the key server's key, not the pinned one")
	}
	if *dialed {
		t.Error("the wrapped key server was dialed for a pinned user")
	}
}

func TestLookupFallsThrough(t *testing.T) {
	dir := t.TempDir()
	bob := annUser()
	bob.Name = "bob@example.com"
	bob.PublicKey = bobKey

	ks, dialed := dial(t, dir, map[upspin.UserName]*upspin.User{"bob@example.com": bob})

	got, err := ks.Lookup("bob@example.com")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got.PublicKey != bobKey {
		t.Errorf("Lookup = %q; want the key server's record", got.PublicKey)
	}
	if !*dialed {
		t.Error("the wrapped key server was not dialed for an unpinned user")
	}

	if _, err := ks.Lookup("nobody@example.com"); !errors.Is(errors.NotExist, err) {
		t.Errorf("Lookup of unknown user = %v; want NotExist", err)
	}
}

// TestDamagedPinDoesNotFallThrough is the security property that makes pinning
// worth anything: if a pinned record cannot be used, the lookup fails. Falling
// back to the key server would let anyone who can corrupt a file in the key
// directory replace a pinned key with one of their choosing.
func TestDamagedPinDoesNotFallThrough(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ann@example.com"), []byte("\tnot: [yaml"), 0600); err != nil {
		t.Fatal(err)
	}

	impostor := annUser()
	impostor.PublicKey = bobKey
	ks, _ := dial(t, dir, map[upspin.UserName]*upspin.User{"ann@example.com": impostor})

	if _, err := ks.Lookup("ann@example.com"); err == nil {
		t.Fatal("Lookup succeeded despite a damaged pinned record")
	}
}

// TestNoKeyDir checks that the wrapper is inert when no key directory is
// configured, so that adding it to the transports changes nothing by default.
func TestNoKeyDir(t *testing.T) {
	ann := annUser()
	ks, dialed := dial(t, "", map[upspin.UserName]*upspin.User{"ann@example.com": ann})

	got, err := ks.Lookup("ann@example.com")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got.PublicKey != annKey {
		t.Errorf("Lookup = %q; want %q", got.PublicKey, annKey)
	}
	if !*dialed {
		t.Error("the wrapped key server was not dialed")
	}
}

// TestPutAddressesKeyServer checks that Put is not diverted to the local
// directory: pinning is done by "upspin keytrust", and Put still means "tell
// the key server".
func TestPutAddressesKeyServer(t *testing.T) {
	dir := t.TempDir()
	base := map[upspin.UserName]*upspin.User{}
	ks, _ := dial(t, dir, base)

	ann := annUser()
	if err := ks.Put(ann); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, ok := base["ann@example.com"]; !ok {
		t.Error("Put did not reach the wrapped key server")
	}
	if _, err := os.Stat(filepath.Join(dir, "ann@example.com")); err == nil {
		t.Error("Put wrote to the key directory")
	}
}

// TestKeyServerOutranksDiscovery covers the order between the two sources that
// are not pinned. A key server is named in the configuration, deliberately,
// where discovery is a standing willingness to ask any domain about its own
// users, so the key server answers first and discovery answers for the users
// it does not know.
func TestKeyServerOutranksDiscovery(t *testing.T) {
	dir := t.TempDir()

	// The key server holds a record for bob, and his domain publishes a
	// different key for him.
	fromServer := annUser()
	fromServer.Name = "bob@example.com"
	fromServer.PublicKey = annKey
	fromDomain := annUser()
	fromDomain.Name = "bob@example.com"
	fromDomain.PublicKey = bobKey

	// Carol the key server does not know at all. A key server that knows
	// nobody is the shape of a configuration that names none.
	onlyPublished := annUser()
	onlyPublished.Name = "carol@example.com"
	onlyPublished.PublicKey = bobKey

	svc, dialed := dial(t, dir, map[upspin.UserName]*upspin.User{fromServer.Name: fromServer})
	s := svc.(*server)
	s.discovery = &discovery{domains: map[string]*published{
		"example.com": {
			users: map[upspin.UserName]*upspin.User{
				fromDomain.Name:    fromDomain,
				onlyPublished.Name: onlyPublished,
			},
			// Fresh, so that consulting it fetches nothing.
			lastTry: time.Now(),
		},
	}}

	got, err := s.Lookup(fromServer.Name)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got.PublicKey != annKey {
		t.Errorf("Lookup = %q; want the key server's record", got.PublicKey)
	}
	if !*dialed {
		t.Error("the key server was not consulted for an unpinned user")
	}

	got, err = s.Lookup(onlyPublished.Name)
	if err != nil {
		t.Fatalf("Lookup of a user the key server does not know: %v", err)
	}
	if got.PublicKey != bobKey {
		t.Errorf("Lookup = %q; want the record the domain publishes", got.PublicKey)
	}

	// A user neither knows is still absent, and the error is the key
	// server's, since that is the source the configuration named.
	if _, err := s.Lookup("nobody@example.com"); !errors.Is(errors.NotExist, err) {
		t.Errorf("Lookup of an unknown user = %v; want NotExist", err)
	}
}

// TestStalePinIsRefused covers the answer to the problem that nothing in
// Upspin pushes a key change. A record pinned before its owner rotated names a
// key they no longer hold; wrapping a file to it loses them access, and
// nothing says so. When a record published under a trust anchor is already in
// hand and disagrees, the lookup fails instead.
func TestStalePinIsRefused(t *testing.T) {
	dir := t.TempDir()
	pinned := annUser() // ann@example.com, holding annKey
	if err := Write(dir, pinned); err != nil {
		t.Fatal(err)
	}
	rotated := annUser()
	rotated.PublicKey = bobKey

	for _, test := range []struct {
		name string
		// install puts a published record where a lookup will already
		// have it, without any fetching.
		install func(s *server, u *upspin.User)
	}{
		{"delegated set", func(s *server, u *upspin.User) {
			s.sets = &sets{users: map[upspin.UserName]*upspin.User{u.Name: u}}
		}},
		{"discovery", func(s *server, u *upspin.User) {
			s.discovery = &discovery{domains: map[string]*published{
				"example.com": {users: map[upspin.UserName]*upspin.User{u.Name: u}},
			}}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			svc, _ := dial(t, dir, nil)
			s := svc.(*server)

			// Agreement is silent: the pin is used, as always.
			test.install(s, pinned)
			got, err := s.Lookup(pinned.Name)
			if err != nil {
				t.Fatalf("Lookup with an agreeing record: %v", err)
			}
			if got.PublicKey != annKey {
				t.Errorf("Lookup = %q; want the pinned key", got.PublicKey)
			}

			// Disagreement is not.
			test.install(s, rotated)
			if _, err := s.Lookup(pinned.Name); err == nil {
				t.Fatal("Lookup answered with a pinned record known to be superseded")
			} else if !strings.Contains(err.Error(), "out of date") {
				t.Errorf("Lookup error = %v; want it to say the pin is out of date", err)
			}
		})
	}
}

// TestStaleCheckNeverFetches makes sure the check costs nothing: it must look
// only at records already in hand, never provoke a fetch of its own, or every
// lookup of a pinned user would reach the network and pinning would buy
// nothing.
func TestStaleCheckNeverFetches(t *testing.T) {
	dir := t.TempDir()
	if err := Write(dir, annUser()); err != nil {
		t.Fatal(err)
	}
	svc, _ := dial(t, dir, nil)
	s := svc.(*server)

	// A set that has never been read, and whose path could not be read
	// here in any case: peeking at it must not try.
	s.sets = &sets{paths: []upspin.PathName{"nobody@example.net/Keys"}}
	s.discovery = &discovery{}

	if _, err := s.Lookup("ann@example.com"); err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	s.sets.mu.Lock()
	tried := !s.sets.lastTry.IsZero()
	s.sets.mu.Unlock()
	if tried {
		t.Error("checking a pinned record provoked a fetch of the delegated sets")
	}
}

// TestKeyServerAttestation covers what a signed record on the wire is for. A
// key server is otherwise believed absolutely: it can return any key for any
// user, and a client will wrap the keys of the files it shares to whatever it
// is handed. An attestation moves that trust to a key the reader pinned.
func TestKeyServerAttestation(t *testing.T) {
	dir := t.TempDir()
	if err := WriteAnchor(dir, "example.com", annUser()); err != nil {
		t.Fatal(err)
	}
	f, _ := anchorFactotum(t)
	attested, err := Sign(f, anchorName, attestedUser()) // carol@example.com, holding bobKey
	if err != nil {
		t.Fatal(err)
	}

	// What the key server returns: the right user, but with a key of the
	// server's choosing, and the genuine attestation attached. The
	// attested record must win, so the substitution fails.
	served := func() *upspin.User {
		return &upspin.User{
			Name:        "carol@example.com",
			Dirs:        []upspin.Endpoint{{Transport: upspin.Remote, NetAddr: "dir.example.com:443"}},
			Stores:      []upspin.Endpoint{{Transport: upspin.Remote, NetAddr: "store.example.com:443"}},
			PublicKey:   annKey, // not the attested key
			Attestation: attested,
		}
	}

	t.Run("attested record replaces what the server sent", func(t *testing.T) {
		ks, _ := dial(t, dir, map[upspin.UserName]*upspin.User{"carol@example.com": served()})
		got, err := ks.Lookup("carol@example.com")
		if err != nil {
			t.Fatalf("Lookup: %v", err)
		}
		if got.PublicKey != bobKey {
			t.Errorf("Lookup = %q; want the attested key, not the key server's", got.PublicKey)
		}
	})

	t.Run("an attestation that does not verify is refused", func(t *testing.T) {
		u := served()
		// Alter a digit of the attested key: a signature over the
		// record no longer holds.
		coord := strings.Split(string(bobKey), "\n")[1]
		u.Attestation = []byte(strings.Replace(string(attested), coord, "1"+coord[1:], 1))
		ks, _ := dial(t, dir, map[upspin.UserName]*upspin.User{"carol@example.com": u})
		if _, err := ks.Lookup("carol@example.com"); err == nil {
			t.Fatal("Lookup accepted an attestation that does not verify")
		} else if !strings.Contains(err.Error(), "does not verify") {
			t.Errorf("Lookup error = %v; want it to say the attestation does not verify", err)
		}
	})

	t.Run("no anchor pinned leaves the record as it was", func(t *testing.T) {
		// With nothing pinned for the domain there is nothing to check
		// against, so the server's answer is as good, and as bad, as
		// it has always been.
		bare := t.TempDir()
		ks, _ := dial(t, bare, map[upspin.UserName]*upspin.User{"carol@example.com": served()})
		got, err := ks.Lookup("carol@example.com")
		if err != nil {
			t.Fatalf("Lookup: %v", err)
		}
		if got.PublicKey != annKey {
			t.Errorf("Lookup = %q; want the key server's own answer", got.PublicKey)
		}
	})

	t.Run("a record with no attestation is unaffected", func(t *testing.T) {
		u := served()
		u.Attestation = nil
		ks, _ := dial(t, dir, map[upspin.UserName]*upspin.User{"carol@example.com": u})
		got, err := ks.Lookup("carol@example.com")
		if err != nil {
			t.Fatalf("Lookup: %v", err)
		}
		if got.PublicKey != annKey {
			t.Errorf("Lookup = %q; want the key server's own answer", got.PublicKey)
		}
	})
}

// selfConfig returns a configuration for ann@example.com holding her key and
// the two endpoints her record should report, with keydir set to dir.
func selfConfig(t *testing.T, dir string) upspin.Config {
	t.Helper()
	f, _ := anchorFactotum(t) // Holds annKey.
	cfg := config.SetUserName(config.New(), "ann@example.com")
	cfg = config.SetFactotum(cfg, f)
	cfg = config.SetDirEndpoint(cfg, upspin.Endpoint{Transport: upspin.Remote, NetAddr: "dir.example.com:443"})
	cfg = config.SetStoreEndpoint(cfg, upspin.Endpoint{Transport: upspin.Remote, NetAddr: "store.example.com:443"})
	if dir != "" {
		cfg = config.SetValue(cfg, ConfigKey, dir)
	}
	return cfg
}

// dialAs is dial, for a caller that supplies its own config and endpoint.
func dialAs(t *testing.T, cfg upspin.Config, e upspin.Endpoint, base map[upspin.UserName]*upspin.User) (upspin.KeyServer, *bool) {
	t.Helper()
	dialed := new(bool)
	svc, err := Wrap(&fakeKey{dialed: dialed, users: base}).Dial(cfg, e)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	return svc.(upspin.KeyServer), dialed
}

// TestUnassignedAnswersOwnUser covers the configuration that names no key
// server at all. It must still be able to name itself: every operation on its
// own tree resolves its own name, so without this the user could reach the
// users she had pinned but not her own files.
func TestUnassignedAnswersOwnUser(t *testing.T) {
	dir := t.TempDir()
	ks, dialed := dialAs(t, selfConfig(t, dir), upspin.Endpoint{Transport: upspin.Unassigned}, nil)

	got, err := ks.Lookup("ann@example.com")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if want := annUser(); got.Name != want.Name || got.PublicKey != want.PublicKey ||
		len(got.Dirs) != 1 || got.Dirs[0] != want.Dirs[0] ||
		len(got.Stores) != 1 || got.Stores[0] != want.Stores[0] {
		t.Errorf("Lookup = %+v; want %+v", got, want)
	}
	if *dialed {
		t.Error("the wrapped key server was dialed for the config's own user")
	}

	// Nobody else, though: the configuration speaks for itself alone, and
	// that is what keeps the pinned directory a complete substitute for a
	// key server rather than a cache in front of one.
	if _, err := ks.Lookup("bob@example.com"); err == nil {
		t.Error("Lookup of another unpinned user succeeded")
	}
}

// TestPinOutranksOwnUser: the configuration answering for itself is the last
// resort, not a new authority. A pinned record still wins, so a user who has
// deliberately pinned her own record, perhaps one attested by her domain, gets
// that record and not the one assembled from her config.
func TestPinOutranksOwnUser(t *testing.T) {
	dir := t.TempDir()
	pinned := annUser()
	pinned.Dirs = []upspin.Endpoint{{Transport: upspin.Remote, NetAddr: "other.example.com:443"}}
	if err := Write(dir, pinned); err != nil {
		t.Fatal(err)
	}
	ks, _ := dialAs(t, selfConfig(t, dir), upspin.Endpoint{Transport: upspin.Unassigned}, nil)

	got, err := ks.Lookup("ann@example.com")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got.Dirs[0] != pinned.Dirs[0] {
		t.Errorf("Lookup returned the config's endpoint, not the pinned one")
	}
}

// TestNamedKeyServerIsAskedForOwnUser is the reason the answer above is
// confined to the unassigned transport. A configuration that names a key
// server must still ask it about its own user, or "upspin user" could no
// longer report a configuration that disagrees with the record the server
// holds: it would be comparing the configuration with itself.
func TestNamedKeyServerIsAskedForOwnUser(t *testing.T) {
	stored := annUser()
	stored.PublicKey = bobKey
	ks, dialed := dialAs(t, selfConfig(t, ""), upspin.Endpoint{Transport: upspin.InProcess},
		map[upspin.UserName]*upspin.User{"ann@example.com": stored})

	got, err := ks.Lookup("ann@example.com")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got.PublicKey != bobKey {
		t.Errorf("Lookup answered from the configuration, not from the key server")
	}
	if !*dialed {
		t.Error("the wrapped key server was not dialed for the config's own user")
	}
}
