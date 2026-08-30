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

// attestedSchema is an ordinary cluster, with a key server, so that the path a
// signed record takes through one can be exercised: stored by the server,
// carried over the wire, and checked by the client against an anchor of its
// own.
const attestedSchema = `
users:
  - name: pat@example.org
  - name: quinn@example.org
servers:
  - name: keyserver
  - name: storeserver
  - name: dirserver
    flags:
      kind: server
domain: example.org
`

const (
	pat   = upspin.UserName("pat@example.org")
	quinn = upspin.UserName("quinn@example.org")
)

// TestKeyServerAttestation checks that a key server carrying an attestation
// stops being a party that must be trusted. The server is honest here, and
// then dishonest: it serves a record whose key it has changed, keeping the
// signature it was given, which is the substitution a key server is in a
// position to make and which nothing used to detect.
func TestKeyServerAttestation(t *testing.T) {
	schema, err := upbox.SchemaFromYAML(attestedSchema)
	if err != nil {
		t.Fatalf("setting up schema: %v", err)
	}
	if err := schema.Start(); err != nil {
		t.Fatalf("starting schema: %v", err)
	}
	defer schema.Stop()

	// pat pins trust anchors; quinn does not, and so believes the key
	// server as everyone had to before.
	tmp := t.TempDir()
	cfgFile := schema.Config(string(pat))
	cfg, err := os.ReadFile(cfgFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgFile, append(cfg, []byte("keydir: "+tmp+"\n")...), 0644); err != nil {
		t.Fatal(err)
	}

	// The key of another user in the cluster, to substitute for quinn's.
	otherKey, err := os.ReadFile(filepath.Join(schema.Dir, string(pat), "public.upspinkey"))
	if err != nil {
		t.Fatal(err)
	}

	attested := filepath.Join(tmp, "quinn.attested")
	tampered := filepath.Join(tmp, "quinn.tampered")

	tests := []cmdTest{
		{
			// pat decides that pat speaks for example.org. Nothing
			// else in the cluster knows or cares.
			"pin an anchor for the domain",
			pat,
			do("keytrust -add -anchor -force pat@example.org"),
			"",
			expect("pinned pat@example.org as the trust anchor for example.org"),
		},
		{
			"attest to the other user's record",
			pat,
			do("keysign quinn@example.org"),
			"",
			saveSubstituted(attested, tampered, string(otherKey)),
		},
		{
			// The record is quinn's to publish, and it carries
			// pat's signature over it.
			"publish the attested record to the key server",
			quinn,
			do("user -put -in=" + attested),
			"",
			expectNoOutput(),
		},
		{
			// The attestation survived the key server's storage
			// and the wire, and was checked against the anchor.
			"the key server's answer is attested",
			pat,
			do("user quinn@example.org"),
			"",
			expect("name: quinn@example.org", "# fingerprint: SHA256:", "# attested by "),
		},
		{
			// Now the record is published with a different key,
			// keeping the signature: what a key server, or anyone
			// who can write to one, is in a position to do.
			"publish a record whose key does not match its signature",
			quinn,
			do("user -put -in=" + tampered),
			"",
			expectNoOutput(),
		},
		{
			"the substitution is refused",
			pat,
			do("user quinn@example.org"),
			"",
			fail("does not verify"),
		},
		{
			// Someone with no anchor pinned has nothing to check
			// against and believes the server, exactly as before.
			// The change takes nothing away from those who do not
			// use it.
			"a client with no anchor is unaffected",
			quinn,
			do("user quinn@example.org"),
			"",
			expect("name: quinn@example.org"),
		},
	}

	for _, test := range tests {
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

// saveSubstituted is a post function that writes the attested record on
// standard output to the file good, and to the file bad a copy whose public
// key has been replaced with otherKey while the signature is left alone.
func saveSubstituted(good, bad, otherKey string) func(t *testing.T, r *runner, cmd *cmdTest, stdout, stderr string) {
	return func(t *testing.T, r *runner, cmd *cmdTest, stdout, stderr string) {
		if stderr != "" {
			t.Fatalf("%q: unexpected error:\n\t%q", cmd.name, stderr)
		}
		if !strings.Contains(stdout, "\n---\nsignatures:\n") {
			t.Fatalf("%q: no attestation in output:\n%s", cmd.name, stdout)
		}
		if err := os.WriteFile(good, []byte(stdout), 0600); err != nil {
			t.Fatal(err)
		}

		// The record holds the key as an indented YAML block, so
		// replace it a coordinate at a time.
		want := strings.Split(strings.TrimSpace(otherKey), "\n")
		if len(want) != 3 {
			t.Fatalf("unexpected key format: %q", otherKey)
		}
		out := stdout
		record, _, ok := strings.Cut(stdout, "\n---\n")
		if !ok {
			t.Fatal("no document marker")
		}
		have := strings.Split(strings.TrimSpace(record), "\n")
		for i, line := range have {
			line = strings.TrimSpace(line)
			if line == want[1] || line == want[2] {
				t.Fatal("the two users share a key; the test cannot substitute one for the other")
			}
			// The two coordinates are the long decimal lines.
			if len(line) > 60 && i > 0 {
				which := 1
				if strings.Contains(out, "  "+want[1]) {
					which = 2
				}
				out = strings.Replace(out, line, want[which], 1)
			}
		}
		if out == stdout {
			t.Fatal("the test did not substitute a key")
		}
		if err := os.WriteFile(bad, []byte(out), 0600); err != nil {
			t.Fatal(err)
		}
	}
}
