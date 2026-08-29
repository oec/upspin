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

const (
	annKey = upspin.PublicKey("p256\n86754568856409436056886548963722747418663925733852968840719951502625645703023\n55374006944977701639377273685946154797448684848748065688191847332792959379206\n")
	bobKey = upspin.PublicKey("p256\n6640270742675236934700552659758623510932789581985633007789325329362331148012\n68892645101823987570169861213316538980647268870890981023717754447508722389034\n")
)

func annUser() *upspin.User {
	return &upspin.User{
		Name:      "ann@example.com",
		Dirs:      []upspin.Endpoint{{Transport: upspin.Remote, NetAddr: "dir.example.com:443"}},
		Stores:    []upspin.Endpoint{{Transport: upspin.Remote, NetAddr: "store.example.com:443"}},
		PublicKey: annKey,
	}
}

func TestWriteReadRemove(t *testing.T) {
	dir := t.TempDir()
	want := annUser()

	if err := Write(dir, want); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, err := Read(dir, want.Name)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got.Name != want.Name || got.PublicKey != want.PublicKey {
		t.Errorf("Read = %+v; want %+v", got, want)
	}
	if len(got.Dirs) != 1 || got.Dirs[0] != want.Dirs[0] {
		t.Errorf("Read dirs = %v; want %v", got.Dirs, want.Dirs)
	}

	// The name is canonicalized on the way in and on the way out, so a
	// lookup that differs only in the case of the domain must still hit.
	if _, err := Read(dir, "ann@EXAMPLE.com"); err != nil {
		t.Errorf("Read with uppercase domain: %v", err)
	}

	// The file is written under the user's name, so that a record can be
	// installed or inspected with ordinary file tools.
	if _, err := os.Stat(filepath.Join(dir, "ann@example.com")); err != nil {
		t.Errorf("record not stored under the user name: %v", err)
	}

	if err := Remove(dir, want.Name); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := Read(dir, want.Name); !errors.Is(errors.NotExist, err) {
		t.Errorf("Read after Remove: err = %v; want NotExist", err)
	}
	if err := Remove(dir, want.Name); !errors.Is(errors.NotExist, err) {
		t.Errorf("Remove of absent record: err = %v; want NotExist", err)
	}
}

func TestReadErrors(t *testing.T) {
	dir := t.TempDir()

	if _, err := Read(dir, "nobody@example.com"); !errors.Is(errors.NotExist, err) {
		t.Errorf("Read of absent record: err = %v; want NotExist", err)
	}

	// A record that is present but unusable must be reported, never
	// treated as absent: falling through to a key server would silently
	// undo the pin.
	for _, test := range []struct {
		name string
		file upspin.UserName
		data string
	}{
		{"malformed YAML", "bad@example.com", "\tthis is not: [yaml"},
		{"name mismatch", "bad@example.com", "name: someone@else.com\n"},
		{"no public key", "bad@example.com", "name: bad@example.com\ndirs:\n- remote,d:443\n"},
		{"unparseable key", "bad@example.com", "name: bad@example.com\ndirs:\n- remote,d:443\npublickey: |\n  not a key\n"},
		{"no dirs", "bad@example.com", "name: bad@example.com\npublickey: |\n  " + string(annKey)},
	} {
		t.Run(test.name, func(t *testing.T) {
			file := filepath.Join(dir, string(test.file))
			if err := os.WriteFile(file, []byte(test.data), 0600); err != nil {
				t.Fatal(err)
			}
			defer os.Remove(file)
			_, err := Read(dir, test.file)
			if err == nil {
				t.Fatal("Read succeeded; want error")
			}
			if errors.Is(errors.NotExist, err) {
				t.Errorf("Read = NotExist (%v); an unusable record must not read as absent", err)
			}
		})
	}
}

// TestReadTraversal checks that a hostile user name cannot escape the key
// directory, since the name becomes part of a file name.
func TestReadTraversal(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []upspin.UserName{
		"../../etc/passwd",
		"a/b@example.com",
		"..",
		"",
	} {
		if _, err := Read(dir, name); err == nil {
			t.Errorf("Read(%q) succeeded; want error", name)
		} else if errors.Is(errors.IO, err) {
			t.Errorf("Read(%q) reached the file system: %v", name, err)
		}
	}
}

func TestList(t *testing.T) {
	dir := t.TempDir()

	// A directory that does not exist holds no pins, and is not an error.
	got, err := List(filepath.Join(dir, "absent"))
	if err != nil || got != nil {
		t.Errorf("List of absent directory = %v, %v; want nil, nil", got, err)
	}

	ann := annUser()
	if err := Write(dir, ann); err != nil {
		t.Fatal(err)
	}
	bob := annUser()
	bob.Name = "bob@example.com"
	bob.PublicKey = bobKey
	if err := Write(dir, bob); err != nil {
		t.Fatal(err)
	}
	// Neither a subdirectory nor a file that is not a user name is a pin.
	if err := os.Mkdir(filepath.Join(dir, "trust-anchors"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "README"), nil, 0600); err != nil {
		t.Fatal(err)
	}

	names, err := List(dir)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	want := []upspin.UserName{"ann@example.com", "bob@example.com"}
	if len(names) != len(want) {
		t.Fatalf("List = %v; want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Errorf("List[%d] = %q; want %q", i, names[i], want[i])
		}
	}
}

func TestDir(t *testing.T) {
	base := config.SetUserName(config.New(), "ann@example.com")

	if got, err := Dir(base); got != "" || err != nil {
		t.Errorf("Dir with no %s = %q, %v; want \"\", nil", ConfigKey, got, err)
	}
	if got, err := Dir(nil); got != "" || err != nil {
		t.Errorf("Dir(nil) = %q, %v; want \"\", nil", got, err)
	}

	cfg := config.SetValue(base, ConfigKey, "/etc/upspin/keys")
	if got, err := Dir(cfg); got != "/etc/upspin/keys" || err != nil {
		t.Errorf("Dir = %q, %v; want /etc/upspin/keys", got, err)
	}

	// A relative path is rejected: servers do not run in a predictable
	// working directory, so it would not mean what it appears to mean.
	cfg = config.SetValue(base, ConfigKey, "keys")
	if _, err := Dir(cfg); err == nil {
		t.Error("Dir of a relative path succeeded; want error")
	}

	home, err := homedir()
	if err != nil {
		t.Skipf("no home directory: %v", err)
	}
	cfg = config.SetValue(base, ConfigKey, "~/upspin/keys")
	if got, err := Dir(cfg); got != filepath.Join(home, "upspin/keys") || err != nil {
		t.Errorf("Dir of ~ path = %q, %v; want %q", got, err, filepath.Join(home, "upspin/keys"))
	}
}
