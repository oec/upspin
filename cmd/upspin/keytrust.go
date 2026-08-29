// Copyright 2026 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"

	yaml "gopkg.in/yaml.v2"

	"upspin.io/errors"
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

With no flags, keytrust lists the pinned users and the trusted roots,
with their key fingerprints, or prints the complete record for each
user named as an argument.

With -add, keytrust pins one user. The record is read from the file
named by -in, or, if -in is absent, from the key server. Because a
pinned record must not be replaced by whatever a key server happens to
return, adding a user who is already pinned is refused; remove the old
record first.

Pinning a key that has not been verified is pointless, so -add
requires one of three things. Either the record carries an attestation
that verifies against a trusted root already pinned for its domain, in
which case nothing more is needed; or -fingerprint gives the
fingerprint the key must have; or -force pins the key unchecked.
Obtain a fingerprint from its owner by some means an attacker does not
control, such as over the telephone, and see it for a given key with

	upspin user <username>

With -add and -root, keytrust pins a user as the trusted root for a
domain: the key entitled to attest for every user in it, so that those
users can be pinned on the strength of that one key rather than
verified one by one. The domain defaults to the domain of the user
being pinned, and -domain names another. A root is the key on which
all the others rest, so it must itself be verified: -fingerprint or
-force is always required.

With -remove, keytrust deletes the record for each user named, or,
with -root, the trusted root for each domain named.

See the keysign command for producing an attested record.
`
	fs := flag.NewFlagSet("keytrust", flag.ExitOnError)
	add := fs.Bool("add", false, "add a pinned user record")
	remove := fs.Bool("remove", false, "remove pinned user records")
	root := fs.Bool("root", false, "the record is a trusted root, entitled to attest for a domain")
	domain := fs.String("domain", "", "the `domain` a trusted root attests for (default: the root's own domain)")
	inFile := fs.String("in", "", "`file` holding the user record to pin (default: ask the key server)")
	fingerprint := fs.String("fingerprint", "", "require the key to have this `fingerprint` before pinning it")
	force := fs.Bool("force", false, "pin the key without verifying its fingerprint")
	s.ParseFlags(fs, args, help,
		"keytrust [username...]\n"+
			"              keytrust -add [-in=file] [-fingerprint=fp] [-force] username\n"+
			"              keytrust -add -root [-domain=name] [-fingerprint=fp] [-force] username\n"+
			"              keytrust -remove username...\n"+
			"              keytrust -remove -root domain...")

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
		s.keytrustAdd(fs, dir, *inFile, *fingerprint, *force, *root, *domain)
	case *remove:
		if fs.NArg() == 0 {
			usageAndExit(fs)
		}
		if *inFile != "" || *fingerprint != "" || *force {
			s.Exitf("-in, -fingerprint and -force are only used with -add")
		}
		s.keytrustRemove(fs, dir, *root, *domain)
	default:
		if *inFile != "" || *fingerprint != "" || *force || *root || *domain != "" {
			s.Exitf("-in, -fingerprint, -force, -root and -domain are only used with -add or -remove")
		}
		s.keytrustList(fs, dir)
	}
}

// keytrustAdd pins one user record, or one trusted root.
func (s *State) keytrustAdd(fs *flag.FlagSet, dir, inFile, fingerprint string, force, root bool, domain string) {
	if fingerprint != "" && force {
		s.Exitf("cannot use -fingerprint and -force together")
	}
	if !root && domain != "" {
		s.Exitf("-domain is only used with -root")
	}

	// Collect the record as bytes, so that an attestation, if there is
	// one, survives to be stored with the record it vouches for.
	var data []byte
	switch {
	case inFile != "":
		if fs.NArg() > 1 {
			s.Exitf("at most one user name may be given with -in")
		}
		data = s.ReadAll(s.GlobOneLocal(inFile))
	default:
		if fs.NArg() != 1 {
			s.Exitf("exactly one user name must be given")
		}
		u, err := s.KeyServer().Lookup(s.cleanUserName(fs.Arg(0)))
		if err != nil {
			s.Exit(err)
		}
		if data, err = yaml.Marshal(*u); err != nil {
			s.Exit(err)
		}
	}

	record, attestation, err := trust.Split(data)
	if err != nil {
		s.Exit(err)
	}
	u := new(upspin.User)
	if err := yaml.Unmarshal(record, u); err != nil {
		s.Exit(err)
	}
	u.Name = s.cleanUserName(string(u.Name))
	if fs.NArg() == 1 && inFile != "" && s.cleanUserName(fs.Arg(0)) != u.Name {
		s.Exitf("user name given does not match the one read from %s", inFile)
	}
	if err := trust.Validate(u); err != nil {
		s.Exit(err)
	}

	// An attestation stands in for verifying the fingerprint by hand: the
	// holder of the domain's trusted root has already vouched for the
	// record. A root itself has nothing above it to vouch for it, so it
	// must always be verified directly.
	verified := false
	if attestation != nil && !root {
		if _, err := trust.Accept(dir, data); err != nil {
			s.Exitf("the attestation on this record was not accepted: %v", err)
		}
		verified = true
	}
	if !verified {
		if fingerprint == "" && !force {
			what := "pinning a key that has not been verified is pointless"
			if root {
				what = "a trusted root vouches for a whole domain and must itself be verified"
			}
			s.Exitf("%s; use -fingerprint to verify it, or -force to pin it anyway", what)
		}
		if got := factotum.Fingerprint(u.PublicKey); fingerprint != "" && got != fingerprint {
			s.Exitf("fingerprint of the key for %s is %s, not %s; the key was NOT pinned", u.Name, got, fingerprint)
		}
	}

	if root {
		if domain == "" {
			if domain, err = domainOf(u.Name); err != nil {
				s.Exit(err)
			}
		}
		if err := trust.WriteRoot(dir, domain, u); err != nil {
			s.Exit(err)
		}
		s.Printf("pinned %s as the trusted root for %s %s\n", u.Name, domain, factotum.Fingerprint(u.PublicKey))
		return
	}

	// Refuse to overwrite a pin. A record that is already pinned has been
	// verified once; replacing it silently with whatever a key server now
	// returns would undo that.
	if _, err := trust.Read(dir, u.Name); err == nil {
		s.Exitf("%s is already pinned; remove it first with 'upspin keytrust -remove %s'", u.Name, u.Name)
	}
	if err := trust.Pin(dir, data); err != nil {
		s.Exit(err)
	}
	how := ""
	if verified {
		how = " (attested)"
	}
	s.Printf("pinned %s %s%s\n", u.Name, factotum.Fingerprint(u.PublicKey), how)
}

// keytrustRemove deletes pinned records or trusted roots.
func (s *State) keytrustRemove(fs *flag.FlagSet, dir string, root bool, domain string) {
	if domain != "" {
		s.Exitf("-domain is not used with -remove; name the domains as arguments")
	}
	for i := 0; i < fs.NArg(); i++ {
		arg := fs.Arg(i)
		if root {
			if err := trust.RemoveRoot(dir, arg); err != nil {
				s.Fail(err)
				continue
			}
			s.Printf("removed the trusted root for %s\n", arg)
			continue
		}
		name := s.cleanUserName(arg)
		if err := trust.Remove(dir, name); err != nil {
			s.Fail(err)
			continue
		}
		s.Printf("removed %s\n", name)
	}
}

// keytrustList prints the pinned users and trusted roots, or the complete
// record of each user named as an argument.
func (s *State) keytrustList(fs *flag.FlagSet, dir string) {
	if fs.NArg() > 0 {
		for i := 0; i < fs.NArg(); i++ {
			name := s.cleanUserName(fs.Arg(i))
			u, err := trust.Read(dir, name)
			if err != nil {
				s.Fail(err)
				continue
			}
			blob, err := yaml.Marshal(*u)
			if err != nil {
				s.Exit(err)
			}
			s.Printf("%s", blob)
			s.Printf("# fingerprint: %s\n\n", factotum.Fingerprint(u.PublicKey))
		}
		return
	}

	names, err := trust.List(dir)
	if err != nil {
		s.Exit(err)
	}
	for _, name := range names {
		u, err := trust.Read(dir, name)
		if err != nil {
			s.Fail(err)
			continue
		}
		s.Printf("%s\t%s\n", name, factotum.Fingerprint(u.PublicKey))
	}

	domains, err := trust.ListRoots(dir)
	if err != nil {
		s.Exit(err)
	}
	for _, domain := range domains {
		u, err := trust.ReadRoot(dir, domain)
		if err != nil {
			s.Fail(err)
			continue
		}
		s.Printf("root for %s\t%s\t%s\n", domain, u.Name, factotum.Fingerprint(u.PublicKey))
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

// domainOf returns the domain component of a user name.
func domainOf(name upspin.UserName) (string, error) {
	_, _, domain, err := user.Parse(name)
	if err != nil {
		return "", errors.E(name, err)
	}
	return domain, nil
}
