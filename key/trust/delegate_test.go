// Copyright 2026 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package trust

import (
	"sync/atomic"
	"testing"
	"time"

	"upspin.io/config"
	"upspin.io/errors"
	"upspin.io/upspin"
)

func TestSets(t *testing.T) {
	base := config.SetUserName(config.New(), "ann@example.com")

	if got, err := Sets(nil); got != nil || err != nil {
		t.Errorf("Sets(nil) = %v, %v; want nil, nil", got, err)
	}
	if got, err := Sets(base); got != nil || err != nil {
		t.Errorf("Sets with no %s = %v, %v; want nil, nil", SetsConfigKey, got, err)
	}

	for _, test := range []struct {
		name  string
		value string
		want  []upspin.PathName
	}{
		{
			// The form a YAML list takes by the time it reaches
			// cfg.Value, which re-marshals what it parsed.
			"list",
			"- dana@example.net/Keys\n- foo@bar.com/pub/Keys",
			[]upspin.PathName{"dana@example.net/Keys", "foo@bar.com/pub/Keys"},
		},
		{
			// One set is the common case, and a bare path is what
			// someone will write for it.
			"bare path",
			"dana@example.net/Keys",
			[]upspin.PathName{"dana@example.net/Keys"},
		},
		{
			"path is cleaned",
			"- dana@example.net//Keys/",
			[]upspin.PathName{"dana@example.net/Keys"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := Sets(config.SetValue(base, SetsConfigKey, test.value))
			if err != nil {
				t.Fatalf("Sets: %v", err)
			}
			if len(got) != len(test.want) {
				t.Fatalf("Sets = %v; want %v", got, test.want)
			}
			for i := range test.want {
				if got[i] != test.want[i] {
					t.Errorf("Sets[%d] = %q; want %q", i, got[i], test.want[i])
				}
			}
		})
	}

	for _, test := range []struct{ name, value string }{
		{"not a path", "- not a user name"},
		{"no user", "- /Keys"},
		// A whole name space is not a directory of keys, and naming
		// one is more likely a mistake than an intention.
		{"name space root", "- dana@example.net/"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got, err := Sets(config.SetValue(base, SetsConfigKey, test.value)); err == nil {
				t.Errorf("Sets = %v; want error", got)
			}
		})
	}
}

func TestReadSetNeedsKeyDir(t *testing.T) {
	// Without a key directory there are no trust anchors, and without
	// those there is no way to tell what a set publishes from what its
	// owner made up. Reading one must fail rather than trust it.
	_, err := readSet(config.New(), "", "dana@example.net/Keys")
	if err == nil {
		t.Fatal("readSet succeeded with no key directory")
	}
	if !contains(err.Error(), ConfigKey) {
		t.Errorf("readSet error = %v; want it to mention %s", err, ConfigKey)
	}
}

// TestRefreshGuard covers the property that keeps a lookup from recursing:
// while a set is being refreshed it is served as it stands, and no second
// refresh begins. Reading a set is itself an Upspin read, which looks up keys,
// so without this a lookup would call back into the lookup that provoked it.
func TestRefreshGuard(t *testing.T) {
	known := &upspin.User{Name: "carol@example.com", PublicKey: annKey}
	s := &sets{
		paths: []upspin.PathName{"dana@example.net/Keys"},
		users: map[upspin.UserName]*upspin.User{known.Name: known},
		// Stale, so that a refresh would be due were one allowed.
		lastTry:    time.Now().Add(-time.Hour),
		refreshing: true,
	}

	// The snapshot answers, and no refresh is attempted: the config here
	// has no directory server bound, so a refresh would fail and, worse,
	// would be a recursive read.
	if got := s.lookup(config.New(), "/keys", known.Name); got != known {
		t.Errorf("lookup during refresh = %v; want the snapshot entry", got)
	}
	if got := s.lookup(config.New(), "/keys", "nobody@example.com"); got != nil {
		t.Errorf("lookup of an absent user during refresh = %v; want nil", got)
	}
	s.mu.Lock()
	stillStale := s.lastTry.Before(time.Now().Add(-time.Minute))
	s.mu.Unlock()
	if !stillStale {
		t.Error("a refresh was begun while one was already running")
	}
}

// TestRefreshInterval checks that a user who is in no set does not provoke a
// refresh on every lookup: a failed attempt counts, and holds off the next.
func TestRefreshInterval(t *testing.T) {
	s := &sets{paths: []upspin.PathName{"dana@example.net/Keys"}}

	// The first lookup tries, and fails: nothing is bound to serve the
	// set. What matters is that it recorded the attempt.
	if got := s.lookup(config.New(), "/keys", "nobody@example.com"); got != nil {
		t.Errorf("lookup = %v; want nil", got)
	}
	s.mu.Lock()
	first := s.lastTry
	s.mu.Unlock()
	if first.IsZero() {
		t.Fatal("a failed refresh was not recorded")
	}

	s.lookup(config.New(), "/keys", "nobody@example.com")
	s.mu.Lock()
	second := s.lastTry
	s.mu.Unlock()
	if !second.Equal(first) {
		t.Error("a second refresh began within the refresh interval")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// fakeReader returns a reader for the sets field of the same name, serving the
// records given, keyed by the set that publishes them, so that precedence
// between sets can be tested without a directory server. A set named in broken
// returns an error instead, standing for one that cannot be read at all.
//
// It replaces nothing global, so tests that use it stay independent of one
// another and may be run in parallel.
//
// Everything readSet returns has already passed Accept, so a record here is
// one whose attestation verified against a pinned anchor.
func fakeReader(records map[upspin.PathName][]*upspin.User, broken ...upspin.PathName) func(upspin.Config, string, upspin.PathName) (map[upspin.UserName]*upspin.User, error) {
	return func(_ upspin.Config, _ string, set upspin.PathName) (map[upspin.UserName]*upspin.User, error) {
		for _, b := range broken {
			if b == set {
				return nil, errors.E(errors.IO, set, errors.Str("unreadable"))
			}
		}
		users := make(map[upspin.UserName]*upspin.User)
		for _, u := range records[set] {
			users[u.Name] = u
		}
		return users, nil
	}
}

// TestConflictingSets covers two delegated key sets that publish different
// records for the same user. Both records are attested, or readSet would not
// have returned them, so both are the user's domain speaking through an anchor
// the reader pinned; nothing in a record says which of them is the newer. The
// reader's configuration decides instead: the set named first wins.
func TestConflictingSets(t *testing.T) {
	first := upspin.PathName("dana@example.net/Keys")
	second := upspin.PathName("ravi@example.net/Keys")
	early := &upspin.User{Name: "carol@example.com", PublicKey: annKey}
	late := &upspin.User{Name: "carol@example.com", PublicKey: bobKey}

	read := fakeReader(map[upspin.PathName][]*upspin.User{
		first:  {early},
		second: {late},
	})

	s := &sets{paths: []upspin.PathName{first, second}, read: read}
	got := s.lookup(config.New(), "/keys", early.Name)
	if got == nil {
		t.Fatal("lookup found no record")
	}
	if got.PublicKey != early.PublicKey {
		t.Errorf("lookup returned the record from the second set; want the first")
	}

	// The order in the configuration is the whole of the decision, so
	// reversing it hands back the other record. Neither lookup reports
	// that a second set disagreed.
	s = &sets{paths: []upspin.PathName{second, first}, read: read}
	got = s.lookup(config.New(), "/keys", early.Name)
	if got == nil {
		t.Fatal("lookup found no record")
	}
	if got.PublicKey != late.PublicKey {
		t.Errorf("lookup did not follow the order of the sets")
	}

	// A user no set publishes is still absent, conflict or no.
	if got := s.lookup(config.New(), "/keys", "nobody@example.com"); got != nil {
		t.Errorf("lookup of an unpublished user = %v; want nil", got)
	}
}

// TestConflictingSetsWithOneUnreadable covers the same conflict when the set
// that would have won cannot be read. Precedence holds only among the sets a
// refresh managed to read: an unreadable set is skipped, so the answer comes
// from the next one that could be read, and the reader is not told that it is
// not the answer they would otherwise have had.
func TestConflictingSetsWithOneUnreadable(t *testing.T) {
	first := upspin.PathName("dana@example.net/Keys")
	second := upspin.PathName("ravi@example.net/Keys")
	early := &upspin.User{Name: "carol@example.com", PublicKey: annKey}
	late := &upspin.User{Name: "carol@example.com", PublicKey: bobKey}

	s := &sets{
		paths: []upspin.PathName{first, second},
		read: fakeReader(map[upspin.PathName][]*upspin.User{
			first:  {early},
			second: {late},
		}, first),
	}
	got := s.lookup(config.New(), "/keys", early.Name)
	if got == nil {
		t.Fatal("an unreadable set discarded the sets after it")
	}
	if got.PublicKey != late.PublicKey {
		t.Errorf("lookup did not fall through to the readable set")
	}

	// If no set can be read at all the snapshot in hand is kept, rather
	// than being emptied by a refresh that reached nothing.
	known := &upspin.User{Name: "carol@example.com", PublicKey: annKey}
	s = &sets{
		paths: []upspin.PathName{first, second},
		read:  fakeReader(nil, first, second),
		users: map[upspin.UserName]*upspin.User{known.Name: known},
	}
	if got := s.lookup(config.New(), "/keys", known.Name); got != known {
		t.Errorf("a failed refresh discarded the snapshot")
	}
}

// TestCheckerPublished covers what a check sees where a lookup sees one
// answer: every source is asked, and each record is labelled with the source
// that published it, so that two sets disagreeing is visible rather than
// hidden behind whichever the configuration names first.
func TestCheckerPublished(t *testing.T) {
	first := upspin.PathName("dana@example.net/Keys")
	second := upspin.PathName("ravi@example.net/Keys")
	early := &upspin.User{Name: "carol@example.com", PublicKey: annKey}
	late := &upspin.User{Name: "carol@example.com", PublicKey: bobKey}

	cfg := config.SetValue(config.New(), ConfigKey, t.TempDir())
	cfg = config.SetValue(cfg, SetsConfigKey, "- "+string(first)+"\n- "+string(second))
	c, err := NewChecker(cfg)
	if err != nil {
		t.Fatalf("NewChecker: %v", err)
	}
	if !c.Sources() {
		t.Fatal("Sources reported nothing to check against")
	}
	c.sets.read = fakeReader(map[upspin.PathName][]*upspin.User{
		first:  {early},
		second: {late},
	})

	got := c.Published(early.Name)
	if len(got) != 2 {
		t.Fatalf("Published returned %d answers; want both sets", len(got))
	}
	for i, want := range []Answer{
		{Source: string(first), User: early},
		{Source: string(second), User: late},
	} {
		if got[i].Source != want.Source {
			t.Errorf("answer %d from %q; want %q", i, got[i].Source, want.Source)
		}
		if got[i].User.PublicKey != want.User.PublicKey {
			t.Errorf("answer %d has the wrong key", i)
		}
	}

	// A user no set publishes has no answers at all, which is what the
	// check reports as "not published" rather than as a disagreement.
	if got := c.Published("nobody@example.com"); len(got) != 0 {
		t.Errorf("Published for an unpublished user = %v; want none", got)
	}
}

// TestSlowSetDoesNotWedgeLookups covers a set that never answers. Nothing in
// the path that reads one has a timeout -- the dial, the Glob, the fetch of
// each record -- and a server whose own users publish the set reads it by
// calling itself, so a stall there is not hypothetical. The lookup must give
// up waiting and answer from what it has; before this it waited for good, and
// since the refreshing flag is only cleared when the read returns, every later
// lookup answered from an empty snapshot without trying again.
func TestSlowSetDoesNotWedgeLookups(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	var reads int32
	s := &sets{
		paths: []upspin.PathName{"ann@example.com/Keys"},
		wait:  10 * time.Millisecond,
		read: func(upspin.Config, string, upspin.PathName) (map[upspin.UserName]*upspin.User, error) {
			if atomic.AddInt32(&reads, 1) == 1 {
				<-release // The first read never finishes on its own.
			}
			return map[upspin.UserName]*upspin.User{"carol@example.com": attestedUser()}, nil
		},
	}

	done := make(chan *upspin.User, 1)
	go func() { done <- s.lookup(nil, "dir", "carol@example.com") }()
	select {
	case u := <-done:
		if u != nil {
			t.Fatalf("lookup returned %v; want nil while the read is stuck", u.Name)
		}
	case <-time.After(20 * time.Second):
		close(release)
		t.Fatal("lookup did not return while a set read was stuck")
	}

	// The stuck read finishes late. Its result must still land, and the
	// sets must be usable again rather than left permanently refreshing.
	close(release)
	deadline := time.Now().Add(20 * time.Second)
	for {
		s.mu.Lock()
		u := s.users["carol@example.com"]
		s.mu.Unlock()
		if u != nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the late read never installed its records")
		}
		time.Sleep(time.Millisecond)
	}
}
