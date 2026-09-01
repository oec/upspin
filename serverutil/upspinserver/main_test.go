// Copyright 2016 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package upspinserver

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"upspin.io/config"
	"upspin.io/key/trust"
	"upspin.io/subcmd"
	"upspin.io/upspin"
)

// TestSetTrust checks the two settings that decide which users a server will
// authenticate, since every Dir and Store method verifies a request signature
// against the caller's key: the directory of pinned records and the Upspin
// directories of published ones.
func TestSetTrust(t *testing.T) {
	// The server configuration directory, holding a key directory beside
	// serverconfig.json, which is how setupserver arranges it.
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "keys"), 0700); err != nil {
		t.Fatal(err)
	}
	elsewhere := t.TempDir()
	notADir := filepath.Join(dir, "serverconfig.json")
	if err := os.WriteFile(notADir, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name     string
		server   subcmd.ServerConfig
		wantDir  string
		wantSets []upspin.PathName
		wantErr  bool
	}{
		{name: "neither"},
		{
			// The common case: the directory sits beside
			// serverconfig.json and is named relative to it.
			name:    "relative key directory",
			server:  subcmd.ServerConfig{KeyDir: "keys"},
			wantDir: filepath.Join(dir, "keys"),
		},
		{
			name:    "absolute key directory",
			server:  subcmd.ServerConfig{KeyDir: elsewhere},
			wantDir: elsewhere,
		},
		{
			// The mistake this catches: a server that starts,
			// serves, and authenticates nobody, because a relative
			// KeyDir landed somewhere that does not exist. Every
			// request then fails its signature check with the
			// error an unknown user gets, and nothing says why.
			name:    "key directory that is not there",
			server:  subcmd.ServerConfig{KeyDir: "kyes"},
			wantErr: true,
		},
		{
			name:    "key directory that is a file",
			server:  subcmd.ServerConfig{KeyDir: "serverconfig.json"},
			wantErr: true,
		},
		{
			name:     "one key set",
			server:   subcmd.ServerConfig{KeyDir: "keys", KeySets: []string{"ann@example.com/Keys"}},
			wantDir:  filepath.Join(dir, "keys"),
			wantSets: []upspin.PathName{"ann@example.com/Keys"},
		},
		{
			// Order is the order of authority between the sets, so
			// it must survive the trip through the config value.
			name: "several key sets",
			server: subcmd.ServerConfig{KeySets: []string{
				"ann@example.com/Keys",
				"bob@example.com/Public/Keys",
			}},
			wantSets: []upspin.PathName{
				"ann@example.com/Keys",
				"bob@example.com/Public/Keys",
			},
		},
		{
			// A whole name space is not a directory of keys.
			// Refusing it here names the file that is wrong;
			// leaving it would fail at the first lookup instead.
			name:    "a set that is not a directory",
			server:  subcmd.ServerConfig{KeySets: []string{"ann@example.com"}},
			wantErr: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg, err := setTrust(config.New(), &test.server, dir)
			if test.wantErr {
				if err == nil {
					t.Fatal("setTrust succeeded; want an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("setTrust: %v", err)
			}
			got, err := trust.Dir(cfg)
			if err != nil {
				t.Fatalf("trust.Dir: %v", err)
			}
			if got != test.wantDir {
				t.Errorf("key directory = %q; want %q", got, test.wantDir)
			}
			sets, err := trust.Sets(cfg)
			if err != nil {
				t.Fatalf("trust.Sets: %v", err)
			}
			if len(sets) != len(test.wantSets) {
				t.Fatalf("sets = %v; want %v", sets, test.wantSets)
			}
			for i, want := range test.wantSets {
				if sets[i] != want {
					t.Errorf("set %d = %q; want %q", i, sets[i], want)
				}
			}
		})
	}
}

func TestCredentialsHiding(t *testing.T) {
	testCases := []struct {
		input  []string
		output string
	}{
		{[]string{}, ""},
		{[]string{"token=apiToken"}, ""},
		{[]string{"gcpBucketName=bucket", "defaultACL=acl", "privateKeyData=key"}, "gcpBucketName=bucket defaultACL=acl"},
		{[]string{"b2csAccount=account", "b2csAppKey=key", "b2csBucketName=bucket"}, "b2csAccount=account b2csBucketName=bucket"},
		{[]string{"openstackContainer=upspin", "openstackRegion=region", "openstackAuthURL=url", "privateOpenstackTenantName=tenant",
			"privateOpenstackUsername=user", "privateOpenstackPassword=password", "privateOpenstackPassword=password"},
			"openstackContainer=upspin openstackRegion=region openstackAuthURL=url"},
	}
	for i, c := range testCases {
		output := fmtStoreConfig(c.input)
		if c.output != output {
			t.Errorf("case %d: got %v, want %v", i, output, c.output)
		}
	}
}

// TestSetTrustTilde checks that a leading tilde in KeyDir means the home
// directory of the user the server runs as, as it does in a client
// configuration file, rather than a directory named "~" under the server
// configuration directory. The directory does not exist, so setTrust fails;
// what the test is after is the path named in the complaint.
func TestSetTrustTilde(t *testing.T) {
	home, err := config.Homedir()
	if err != nil {
		t.Skipf("no home directory: %v", err)
	}
	_, err = setTrust(config.New(), &subcmd.ServerConfig{KeyDir: "~/upspin-keys-that-are-not-there"}, t.TempDir())
	if err == nil {
		t.Fatal("setTrust succeeded; want an error naming the missing directory")
	}
	want := filepath.Join(home, "upspin-keys-that-are-not-there")
	if !strings.Contains(err.Error(), want) {
		t.Errorf("setTrust error = %v; want it to name %s", err, want)
	}
}
