// Copyright 2026 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package trust

import (
	"os"
	"path/filepath"
	"testing"

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
