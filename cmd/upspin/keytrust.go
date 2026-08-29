// Copyright 2026 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"

	yaml "gopkg.in/yaml.v2"

	"upspin.io/factotum"
	"upspin.io/flags"
	"upspin.io/key/trust"
	"upspin.io/upspin"
	"upspin.io/user"
)

func (s *State) keytrust(args ...string) {
	const help = `
Keytrust manages the directory of pinned user records named by the
keydir entry in the configuration file. A pinned record is used as it
stands: the key server is not consulted for that user, and cannot
substitute a key of its own choosing. Since an Upspin user record is
not signed, pinning is the only way to be certain which key belongs
to a user.

With no flags, keytrust lists the pinned users and their key
fingerprints, or prints the complete record for each user named as an
argument.

With -add, keytrust pins one user. The record is read from the file
named by -in, or, if -in is absent, from the key server. Because a
pinned record must not be replaced by whatever a key server happens to
return, adding a user who is already pinned is refused; remove the old
record first.

Pinning a key that has not been verified is pointless, so -add
requires either -fingerprint, giving the fingerprint the key must
have, or -force to pin without checking. Obtain the fingerprint from
its owner by some means an attacker does not control, such as over the
telephone, and see it for a given key with

	upspin user <username>

With -remove, keytrust deletes the record for each user named.
`
	fs := flag.NewFlagSet("keytrust", flag.ExitOnError)
	add := fs.Bool("add", false, "add a pinned user record")
	remove := fs.Bool("remove", false, "remove pinned user records")
	inFile := fs.String("in", "", "`file` holding the user record to pin (default: ask the key server)")
	fingerprint := fs.String("fingerprint", "", "require the key to have this `fingerprint` before pinning it")
	force := fs.Bool("force", false, "pin the key without verifying its fingerprint")
	s.ParseFlags(fs, args, help,
		"keytrust [username...]\n              keytrust -add [-in=file] [-fingerprint=fp] [-force] username\n              keytrust -remove username...")

	if *add && *remove {
		s.Exitf("cannot use -add and -remove together")
	}
	dir, err := trust.Dir(s.Config)
	if err != nil {
		s.Exit(err)
	}
	if dir == "" {
		s.Exitf("no %s entry in the configuration file %s", trust.ConfigKey, flags.Config)
	}

	switch {
	case *add:
		s.keytrustAdd(fs, dir, *inFile, *fingerprint, *force)
	case *remove:
		if fs.NArg() == 0 {
			usageAndExit(fs)
		}
		for i := 0; i < fs.NArg(); i++ {
			name := s.cleanUserName(fs.Arg(i))
			if err := trust.Remove(dir, name); err != nil {
				s.Fail(err)
				continue
			}
			s.Printf("removed %s\n", name)
		}
	default:
		if *inFile != "" || *fingerprint != "" || *force {
			s.Exitf("-in, -fingerprint and -force are only used with -add")
		}
		s.keytrustList(fs, dir)
	}
}

// keytrustAdd pins one user record.
func (s *State) keytrustAdd(fs *flag.FlagSet, dir, inFile, fingerprint string, force bool) {
	if fingerprint == "" && !force {
		s.Exitf("pinning a key that has not been verified is pointless; use -fingerprint to verify it, or -force to pin it anyway")
	}
	if fingerprint != "" && force {
		s.Exitf("cannot use -fingerprint and -force together")
	}

	var u *upspin.User
	if inFile != "" {
		if fs.NArg() > 1 {
			s.Exitf("at most one user name may be given with -in")
		}
		u = new(upspin.User)
		if err := yaml.Unmarshal(s.ReadAll(s.GlobOneLocal(inFile)), u); err != nil {
			s.Exit(err)
		}
		if fs.NArg() == 1 && s.cleanUserName(fs.Arg(0)) != u.Name {
			s.Exitf("user name given does not match the one read from %s", inFile)
		}
	} else {
		if fs.NArg() != 1 {
			s.Exitf("exactly one user name must be given")
		}
		name := s.cleanUserName(fs.Arg(0))
		var err error
		u, err = s.KeyServer().Lookup(name)
		if err != nil {
			s.Exit(err)
		}
	}

	name := s.cleanUserName(string(u.Name))
	u.Name = name

	// Refuse to overwrite a pin. A record that is already pinned has been
	// verified once; replacing it silently with whatever a key server now
	// returns would undo that.
	if _, err := trust.Read(dir, name); err == nil {
		s.Exitf("%s is already pinned; remove it first with 'upspin keytrust -remove %s'", name, name)
	}

	if err := trust.Validate(u); err != nil {
		s.Exit(err)
	}
	got := factotum.Fingerprint(u.PublicKey)
	if fingerprint != "" && got != fingerprint {
		s.Exitf("fingerprint of the key for %s is %s, not %s; the key was NOT pinned", name, got, fingerprint)
	}
	if err := trust.Write(dir, u); err != nil {
		s.Exit(err)
	}
	s.Printf("pinned %s %s\n", name, got)
}

// keytrustList prints the pinned users, or the complete record of each user
// named as an argument.
func (s *State) keytrustList(fs *flag.FlagSet, dir string) {
	var names []upspin.UserName
	if fs.NArg() == 0 {
		var err error
		names, err = trust.List(dir)
		if err != nil {
			s.Exit(err)
		}
	} else {
		for i := 0; i < fs.NArg(); i++ {
			names = append(names, s.cleanUserName(fs.Arg(i)))
		}
	}
	for _, name := range names {
		u, err := trust.Read(dir, name)
		if err != nil {
			s.Fail(err)
			continue
		}
		if fs.NArg() == 0 {
			s.Printf("%s\t%s\n", name, factotum.Fingerprint(u.PublicKey))
			continue
		}
		blob, err := yaml.Marshal(u)
		if err != nil {
			s.Exit(err)
		}
		s.Printf("%s", blob)
		s.Printf("# fingerprint: %s\n\n", factotum.Fingerprint(u.PublicKey))
	}
}

// cleanUserName returns the canonical form of the user name, exiting if it is
// not a valid one.
func (s *State) cleanUserName(name string) upspin.UserName {
	clean, err := user.Clean(upspin.UserName(name))
	if err != nil {
		s.Exit(err)
	}
	return clean
}
