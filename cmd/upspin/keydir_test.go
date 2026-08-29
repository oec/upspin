// Copyright 2026 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
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

	for _, test := range keyDirTests {
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

var keyDirTests = []cmdTest{
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
