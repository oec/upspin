// Copyright 2026 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"upspin.io/upbox"
	"upspin.io/upspin"
)

// keyDirSchema describes a cluster with no keyserver at all. Every user record
// is pinned in a directory shared by the users and the servers, and each
// config names an unassigned key server, so any lookup that is not answered
// from that directory fails.
const keyDirSchema = `
users:
  - name: dana@example.net
  - name: ravi@example.net
servers:
  - name: storeserver
  - name: dirserver
    flags:
      kind: server
usekeydir: true
domain: example.net
`

const (
	dana = upspin.UserName("dana@example.net")
	ravi = upspin.UserName("ravi@example.net")
)

// TestKeyDir exercises a cluster that has no key server, to check that a
// directory of pinned records can carry the whole load: the client resolving
// other users, and the servers resolving the clients that authenticate to
// them.
func TestKeyDir(t *testing.T) {
	schema, err := upbox.SchemaFromYAML(keyDirSchema)
	if err != nil {
		t.Fatalf("setting up schema: %v", err)
	}
	for _, s := range schema.Servers {
		if s.Name == "keyserver" {
			t.Fatal("the schema is supposed to have no keyserver")
		}
	}
	if err := schema.Start(); err != nil {
		t.Fatalf("starting schema: %v", err)
	}
	defer schema.Stop()

	for _, test := range keyDirTests(t, t.TempDir()) {
		r := &runner{
			fs:     flag.NewFlagSet(test.name, flag.PanicOnError),
			schema: schema,
		}
		state, _, ok := setup(r.fs, []string{"-config=" + r.config(test.user), "test"})
		if !ok {
			t.Fatal("setup failed; bad arg list?")
		}
		r.state = state
		t.Run(test.name, r.run(&test))
	}
}

// saveAttested is a post function that writes the attested record on the
// command's standard output to the file good, and a copy with the attested
// key altered to the file bad, so that later commands can read both. The
// files cannot be prepared before the test runs, since the attestation is
// what the command produces.
func saveAttested(good, bad string) func(t *testing.T, r *runner, cmd *cmdTest, stdout, stderr string) {
	return func(t *testing.T, r *runner, cmd *cmdTest, stdout, stderr string) {
		if stderr != "" {
			t.Fatalf("%q: unexpected error:\n\t%q", cmd.name, stderr)
		}
		for _, word := range []string{"name: newbie@example.net", "\n---\nsignature: "} {
			if !strings.Contains(stdout, word) {
				t.Fatalf("%q: output did not contain %q:\n%s", cmd.name, word, stdout)
			}
		}
		if err := os.WriteFile(good, []byte(stdout), 0600); err != nil {
			t.Fatal(err)
		}
		// Swap a digit of the attested public key: the substitution
		// an attestation exists to catch.
		coord := strings.Split(newbieKey, "\n")[1]
		tampered := strings.Replace(stdout, coord, "1"+coord[1:], 1)
		if tampered == stdout {
			t.Fatal("test did not modify the attested key")
		}
		if err := os.WriteFile(bad, []byte(tampered), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

// A valid p256 key, for a user who exists only in these records.
const newbieKey = "p256\n86754568856409436056886548963722747418663925733852968840719951502625645703023\n55374006944977701639377273685946154797448684848748065688191847332792959379206\n"

func keyDirTests(t *testing.T, tmp string) []cmdTest {
	t.Helper()

	// A plain record for a user that no key server knows about. It can
	// only reach a key directory by being carried there, which is what
	// attestation is for.
	plain := filepath.Join(tmp, "newbie.yaml")
	record := "name: newbie@example.net\n" +
		"dirs:\n- remote,dir.example.net:443\n" +
		"stores:\n- remote,store.example.net:443\n" +
		"publickey: |\n  " + strings.ReplaceAll(strings.TrimSuffix(newbieKey, "\n"), "\n", "\n  ") + "\n"
	if err := os.WriteFile(plain, []byte(record), 0600); err != nil {
		t.Fatal(err)
	}
	attested := filepath.Join(tmp, "newbie.attested")
	tampered := filepath.Join(tmp, "newbie.tampered")

	return append(keyDirBasicTests, []cmdTest{
		{
			// dana signs a record for another user in her domain.
			// Nothing checks here that she is entitled to; that is
			// the reader's decision, made by pinning an anchor.
			"attest to a record",
			dana,
			do("keysign -in=" + plain),
			"",
			saveAttested(attested, tampered),
		},
		{
			// Without an anchor pinned for the domain there is nothing
			// to check the attestation against, so it is refused.
			"an attested record with no anchor is refused",
			dana,
			do("keytrust -add -in=" + attested),
			"",
			fail("no trust anchor for example.net"),
		},
		{
			// An anchor vouches for a whole domain, so it must itself
			// be verified; -force stands in for that here.
			"pin a trust anchor",
			dana,
			do("keytrust -add -anchor -force dana@example.net"),
			"",
			expect("pinned dana@example.net as the trust anchor for example.net", "SHA256:"),
		},
		{
			// Now the attestation carries the record, with no
			// fingerprint to check by hand. That is the point of
			// the whole exercise.
			"pin an attested record without verifying it",
			dana,
			do("keytrust -add -in=" + attested),
			"",
			expect("pinned newbie@example.net", "SHA256:", "(attested)"),
		},
		{
			"the attested user resolves like any other",
			dana,
			do("keytrust newbie@example.net"),
			"",
			expect("name: newbie@example.net", "# fingerprint: SHA256:"),
		},
		{
			"a tampered attested record is refused",
			dana,
			do(
				"keytrust -remove newbie@example.net",
				"keytrust -add -in="+tampered,
			),
			"",
			fail("attestation does not verify"),
		},
		{
			"remove the trust anchor",
			dana,
			do("keytrust -remove -anchor example.net"),
			"",
			expect("removed the trust anchor for example.net"),
		},
	}...)
}

var keyDirBasicTests = []cmdTest{
	{
		// The pinned directory is what the client resolves names from,
		// so it must hold every user in the cluster, servers included.
		"keytrust lists the pinned users",
		dana,
		do("keytrust"),
		"",
		expect(
			"dana@example.net", "SHA256:",
			"dirserver@example.net", "SHA256:",
			"ravi@example.net", "SHA256:",
			"storeserver@example.net", "SHA256:",
		),
	},
	{
		// Writing and reading a file exercises the whole chain with no
		// key server present: the dirserver and storeserver must
		// resolve dana's key to verify her request signatures, and the
		// client must resolve its own key to pack the file.
		"write and read a file with no keyserver",
		dana,
		do(
			"mkdir dana@example.net",
			"put dana@example.net/hello",
			"get @/hello",
		),
		"no keyserver was harmed\n",
		expect("no keyserver was harmed\n"),
	},
	{
		"make a public directory",
		dana,
		do("mkdir @/Public"),
		"",
		expectNoOutput(),
	},
	putFile(dana, "dana@example.net/Public/Access", "r,l: all\n*:dana@example.net\n"),
	putFile(dana, "dana@example.net/Public/note", "shared without a keyserver\n"),
	{
		// Sharing requires resolving another user's public key, which
		// can only come from the pinned directory.
		"share reports the readers",
		dana,
		do("share @/Public/note"),
		"",
		expect("all@upspin.io dana@example.net", "dana@example.net/Public/note"),
	},
	{
		"the other user can read the shared file",
		ravi,
		do("get dana@example.net/Public/note"),
		"",
		expect("shared without a keyserver\n"),
	},
	{
		// A user who is not pinned cannot be resolved, because there
		// is no key server to fall back to. This is the property that
		// makes the pinned directory a complete substitute rather than
		// a cache in front of one.
		"an unpinned user cannot be resolved",
		dana,
		do("user nobody@example.net"),
		"",
		fail("request to unassigned service"),
	},
}
