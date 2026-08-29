// Copyright 2026 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package trust

import (
	"testing"
	"time"

	"upspin.io/config"
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
