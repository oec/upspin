// Copyright 2026 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"

	yaml "gopkg.in/yaml.v2"

	"upspin.io/key/trust"
	"upspin.io/upspin"
)

func (s *State) keysign(args ...string) {
	const help = `
Keysign writes to standard output an attested user record: the record
for a user, followed by a signature over it made with the current
user's key.

An attested record can be pinned by anyone who has pinned the signing
key as the trust anchor for that user's domain, without their having
to verify the user's key themselves. Signing the records of a domain's
users is therefore how the holder of its anchor key spares everyone else
the work of checking each key in it by hand.

The record is read from the file named by -in, or, if -in is absent,
looked up for the user named as the argument.

Nothing here checks that the signing key is entitled to speak for the
record's domain; that is the reader's decision, expressed by which key
they pin as the trust anchor for a domain. See the keytrust command,
whose -add -anchor flags pin such an anchor.

A typical use is to attest to a record and send the result to someone
who has already pinned this key as an anchor:

	upspin keysign ann@example.com > ann.attested
`
	fs := flag.NewFlagSet("keysign", flag.ExitOnError)
	inFile := fs.String("in", "", "`file` holding the user record to sign (default: ask the key server)")
	s.ParseFlags(fs, args, help, "keysign [-in=file] [username]")

	f := s.Config.Factotum()
	if f == nil {
		s.Exitf("no factotum available")
	}

	u := new(upspin.User)
	switch {
	case *inFile != "":
		if fs.NArg() > 1 {
			s.Exitf("at most one user name may be given with -in")
		}
		// Any attestation already on the record is replaced by this
		// one, so read past it rather than signing it too.
		record, _, err := trust.Split(s.ReadAll(s.GlobOneLocal(*inFile)))
		if err != nil {
			s.Exit(err)
		}
		if err := yaml.Unmarshal(record, u); err != nil {
			s.Exit(err)
		}
		if fs.NArg() == 1 && s.cleanUserName(fs.Arg(0)) != u.Name {
			s.Exitf("user name given does not match the one read from %s", *inFile)
		}
	default:
		if fs.NArg() != 1 {
			s.Exitf("exactly one user name must be given")
		}
		var err error
		if u, err = s.KeyServer().Lookup(s.cleanUserName(fs.Arg(0))); err != nil {
			s.Exit(err)
		}
	}
	u.Name = s.cleanUserName(string(u.Name))

	data, err := trust.Sign(f, u)
	if err != nil {
		s.Exit(err)
	}
	s.Printf("%s", data)
}
