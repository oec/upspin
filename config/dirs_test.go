// Copyright 2026 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"upspin.io/errors"
)

func TestDirs(t *testing.T) {
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" || runtime.GOOS == "plan9" {
		t.Skip("XDG variables are honoured on Unix")
	}
	user := t.TempDir()
	sys1 := t.TempDir()
	sys2 := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", user)
	t.Setenv("XDG_CONFIG_DIRS", sys1+":"+sys2)

	dirs := Dirs()
	home, err := Homedir()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		filepath.Join(user, "upspin"),
		filepath.Join(home, "upspin"),
		filepath.Join(sys1, "upspin"),
		filepath.Join(sys2, "upspin"),
	}
	if len(dirs) != len(want) {
		t.Fatalf("Dirs = %v, want %v", dirs, want)
	}
	for i := range want {
		if dirs[i] != want[i] {
			t.Errorf("Dirs[%d] = %q, want %q", i, dirs[i], want[i])
		}
	}

	// A name that exists in none of them, so that the test does not
	// depend on what the machine's own home directory holds.
	const name = "config.dirs_test"
	if _, err := Find(name); !errors.Is(errors.NotExist, err) {
		t.Errorf("Find of a missing file: %v, want NotExist", err)
	}
	if got, want := DefaultFile(name), filepath.Join(user, "upspin", name); got != want {
		t.Errorf("DefaultFile with none = %q, want %q", got, want)
	}

	// A system copy is found; a user copy outranks it.
	write := func(dir string) string {
		p := filepath.Join(dir, "upspin", name)
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("username: ann@example.com\nsecrets: none\n"), 0600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	inSys := write(sys2)
	if got, err := Find(name); err != nil || got != inSys {
		t.Errorf("Find = %q, %v; want %q", got, err, inSys)
	}
	if got := DefaultFile(name); got != inSys {
		t.Errorf("DefaultFile = %q, want %q", got, inSys)
	}
	inUser := write(user)
	if got, err := Find(name); err != nil || got != inUser {
		t.Errorf("Find = %q, %v; want %q", got, err, inUser)
	}

	// An absolute name is itself, found or not.
	if got, err := Find(inSys); err != nil || got != inSys {
		t.Errorf("Find of absolute = %q, %v", got, err)
	}
	missing := filepath.Join(sys1, "nothing")
	if _, err := Find(missing); !errors.Is(errors.NotExist, err) {
		t.Errorf("Find of a missing absolute name: %v", err)
	}
	if got := DefaultFile(missing); got != missing {
		t.Errorf("DefaultFile of a missing absolute name = %q", got)
	}

	// The current directory counts for Find, and only for a file: a
	// directory of the same name is not a configuration. It never counts
	// for the default.
	cwd := t.TempDir()
	if err := os.Chdir(cwd); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(cwd, name), 0700); err != nil {
		t.Fatal(err)
	}
	if got, err := Find(name); err != nil || got != inUser {
		t.Errorf("Find beside a directory of that name = %q, %v; want %q", got, err, inUser)
	}
	os.Remove(filepath.Join(cwd, name))
	if err := os.WriteFile(filepath.Join(cwd, name), []byte("username: bob@example.com\nsecrets: none\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := Find(name); err != nil || got != name {
		t.Errorf("Find beside a file of that name = %q, %v; want %q", got, err, name)
	}
	if got := DefaultFile(name); got != inUser {
		t.Errorf("DefaultFile beside a file of that name = %q, want %q", got, inUser)
	}
	os.Remove(filepath.Join(cwd, name))

	// FromFile reads through the same search.
	cfg, err := FromFile(name)
	if err != nil && err != ErrNoFactotum {
		t.Fatalf("FromFile: %v", err)
	}
	if cfg.UserName() != "ann@example.com" {
		t.Errorf("FromFile read %q", cfg.UserName())
	}
}
