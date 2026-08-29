// Copyright 2026 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"

	yaml "gopkg.in/yaml.v2"

	"upspin.io/key/trust"
	"upspin.io/upspin"
	"upspin.io/user"
)

func (s *State) keysign(args ...string) {
	const help = `
Keysign writes to standard output an attested user record: the record
for a user, followed by a signature over it made with the current
user's key.

With -bundle, keysign attests to several records at once and writes
them as a bundle, the form a domain publishes at
/.well-known/upspin/keys for readers that discover records over DNS.
The arguments are then user names, files, or both; a file may hold a
record already attested, in which case the attestation is replaced.

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

or, to publish every user of a domain at once:

	upspin keysign -bundle ann@example.com chris@example.com > keys
`
	fs := flag.NewFlagSet("keysign", flag.ExitOnError)
	inFile := fs.String("in", "", "`file` holding the user record to sign (default: ask the key server)")
	bundle := fs.Bool("bundle", false, "attest to several records and write them as a published bundle")
	s.ParseFlags(fs, args, help, "keysign [-in=file] [username]\n              keysign -bundle username-or-file...")

	f := s.Config.Factotum()
	if f == nil {
		s.Exitf("no factotum available")
	}

	if *bundle {
		if *inFile != "" {
			s.Exitf("-in is not used with -bundle; name the files as arguments")
		}
		if fs.NArg() == 0 {
			usageAndExit(fs)
		}
		var records [][]byte
		for i := 0; i < fs.NArg(); i++ {
			records = append(records, s.attest(f, fs.Arg(i)))
		}
		data, err := trust.Bundle(records)
		if err != nil {
			s.Exit(err)
		}
		s.Printf("%s", data)
		return
	}

	var u *upspin.User
	switch {
	case *inFile != "":
		if fs.NArg() > 1 {
			s.Exitf("at most one user name may be given with -in")
		}
		u = s.recordFromFile(s.GlobOneLocal(*inFile))
		if fs.NArg() == 1 && s.cleanUserName(fs.Arg(0)) != u.Name {
			s.Exitf("user name given does not match the one read from %s", *inFile)
		}
	default:
		if fs.NArg() != 1 {
			s.Exitf("exactly one user name must be given")
		}
		u = s.recordFor(fs.Arg(0))
	}

	data, err := trust.Sign(f, u)
	if err != nil {
		s.Exit(err)
	}
	s.Printf("%s", data)
}

// attest returns an attested record for arg, which names either a local file
// holding a record or a user to look up.
func (s *State) attest(f upspin.Factotum, arg string) []byte {
	var u *upspin.User
	if _, _, _, err := user.Parse(upspin.UserName(arg)); err == nil {
		u = s.recordFor(arg)
	} else {
		u = s.recordFromFile(s.GlobOneLocal(arg))
	}
	data, err := trust.Sign(f, u)
	if err != nil {
		s.Exit(err)
	}
	return data
}

// recordFor returns the record the key server holds for the named user.
func (s *State) recordFor(name string) *upspin.User {
	u, err := s.KeyServer().Lookup(s.cleanUserName(name))
	if err != nil {
		s.Exit(err)
	}
	u.Name = s.cleanUserName(string(u.Name))
	return u
}

// recordFromFile returns the record held in a local file. Any attestation
// already on it is read past rather than signed again, since signing it would
// be signing someone else's signature.
func (s *State) recordFromFile(file string) *upspin.User {
	record, _, err := trust.Split(s.ReadAll(file))
	if err != nil {
		s.Exit(err)
	}
	u := new(upspin.User)
	if err := yaml.Unmarshal(record, u); err != nil {
		s.Exit(err)
	}
	u.Name = s.cleanUserName(string(u.Name))
	return u
}
