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

With no flags, keytrust lists the pinned users and the trust anchors,
with their key fingerprints, or prints the complete record for each
user named as an argument.

With -add, keytrust pins one user. The record is read from the file
named by -in, or, if -in is absent, from the key server. Because a
pinned record must not be replaced by whatever a key server happens to
return, adding a user who is already pinned is refused; remove the old
record first.

Pinning a key that has not been verified is pointless, so -add
requires one of three things. Either the record carries an attestation
that verifies against a trust anchor already pinned for its domain, in
which case nothing more is needed; or -fingerprint gives the
fingerprint the key must have; or -force pins the key unchecked.
Obtain a fingerprint from its owner by some means an attacker does not
control, such as over the telephone, and see it for a given key with

	upspin user <username>

With -add and -anchor, keytrust pins a user as a trust anchor for a
domain: a key entitled to attest for every user in it, so that those
users can be pinned on the strength of that one key rather than
verified one by one. The domain defaults to the domain of the user
being pinned, and -domain names another. An anchor is the key on which
all the others rest, so it must itself be verified: -fingerprint or
-force is always required.

A domain may have more than one anchor, and a record is accepted on a
signature by any of them. That is what makes it possible to replace an
anchor key without arranging for everyone to re-pin at the same
instant: pin the new anchor beside the old, and drop the old one once
the records in circulation carry a signature by the new.

With -remove, keytrust deletes the record for each user named; with
-anchor, every anchor for each domain named; and with -anchor and
-domain, only the anchors named as arguments within that one domain,
leaving any others in place.

With -check, keytrust compares each pinned record, or each of those
named as arguments, against what is published for that user now by the
delegated key sets and by the user's own domain, and reports any that
disagree. Nothing in Upspin pushes a key change, so a pinned record can
outlive the key it names; until it is replaced, files shared with that
user are wrapped to a key they no longer hold, and neither party is
told. A check is how that is found on purpose rather than by the loss
of access it causes. It needs a keysets entry, or keydiscovery, in the
configuration; with neither there is nothing to compare against.

With -export, keytrust writes the pinned record for each user named to
standard output, as it is stored and including its attestation, so that
it can be passed on to someone else.

See the keysign command for producing an attested record.
`
	fs := flag.NewFlagSet("keytrust", flag.ExitOnError)
	add := fs.Bool("add", false, "add a pinned user record")
	remove := fs.Bool("remove", false, "remove pinned user records")
	anchor := fs.Bool("anchor", false, "the record is a trust anchor, entitled to attest for a domain")
	domain := fs.String("domain", "", "the `domain` whose anchors to act on (default: the anchor's own domain)")
	inFile := fs.String("in", "", "`file` holding the user record to pin (default: ask the key server)")
	fingerprint := fs.String("fingerprint", "", "require the key to have this `fingerprint` before pinning it")
	force := fs.Bool("force", false, "pin the key without verifying its fingerprint")
	check := fs.Bool("check", false, "report pinned records that disagree with what is published now")
	export := fs.Bool("export", false, "write pinned records, with their attestations, to standard output")
	s.ParseFlags(fs, args, help,
		"keytrust [username...]\n"+
			"              keytrust -add [-in=file] [-fingerprint=fp] [-force] username\n"+
			"              keytrust -add -anchor [-domain=name] [-fingerprint=fp] [-force] username\n"+
			"              keytrust -remove username...\n"+
			"              keytrust -remove -anchor domain...\n"+
			"              keytrust -remove -anchor -domain=name username...\n"+
			"              keytrust -check [username...]\n"+
			"              keytrust -export username...")

	if n := count(*add, *remove, *check, *export); n > 1 {
		s.Exitf("-add, -remove, -check and -export are mutually exclusive")
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
		s.keytrustAdd(fs, dir, *inFile, *fingerprint, *force, *anchor, *domain)
	case *check:
		if *inFile != "" || *fingerprint != "" || *force || *anchor || *domain != "" {
			s.Exitf("-check takes only user names")
		}
		s.keytrustCheck(fs, dir)
	case *export:
		if fs.NArg() == 0 {
			usageAndExit(fs)
		}
		if *inFile != "" || *fingerprint != "" || *force || *anchor || *domain != "" {
			s.Exitf("-export takes only user names")
		}
		for i := 0; i < fs.NArg(); i++ {
			data, err := trust.ReadRaw(dir, s.cleanUserName(fs.Arg(i)))
			if err != nil {
				s.Fail(err)
				continue
			}
			s.Printf("%s", data)
		}
	case *remove:
		if fs.NArg() == 0 {
			usageAndExit(fs)
		}
		if *inFile != "" || *fingerprint != "" || *force {
			s.Exitf("-in, -fingerprint and -force are only used with -add")
		}
		s.keytrustRemove(fs, dir, *anchor, *domain)
	default:
		if *inFile != "" || *fingerprint != "" || *force || *anchor || *domain != "" {
			s.Exitf("-in, -fingerprint, -force, -anchor and -domain are only used with -add or -remove")
		}
		s.keytrustList(fs, dir)
	}
}

// count returns the number of the flags that are set.
func count(flags ...bool) int {
	n := 0
	for _, f := range flags {
		if f {
			n++
		}
	}
	return n
}

// keytrustCheck compares pinned records with what is published for those users
// now, and reports any that disagree.
func (s *State) keytrustCheck(fs *flag.FlagSet, dir string) {
	checker, err := trust.NewChecker(s.Config)
	if err != nil {
		s.Exit(err)
	}
	if !checker.Sources() {
		s.Exitf("nothing to check against: the configuration names no %s and does not set %s",
			trust.SetsConfigKey, trust.DiscoveryConfigKey)
	}

	// What to check: the users named, or everything pinned, anchors as
	// well, since an anchor going stale is the worse failure of the two.
	type pin struct {
		name   upspin.UserName
		anchor string // the domain, if this is a trust anchor
	}
	var pins []pin
	if fs.NArg() > 0 {
		for i := 0; i < fs.NArg(); i++ {
			pins = append(pins, pin{name: s.cleanUserName(fs.Arg(i))})
		}
	} else {
		names, err := trust.List(dir)
		if err != nil {
			s.Exit(err)
		}
		for _, name := range names {
			pins = append(pins, pin{name: name})
		}
		domains, err := trust.ListAnchors(dir)
		if err != nil {
			s.Exit(err)
		}
		for _, domain := range domains {
			anchors, err := trust.ReadAnchors(dir, domain)
			if err != nil {
				s.Fail(err)
				continue
			}
			for _, u := range anchors {
				pins = append(pins, pin{name: u.Name, anchor: domain})
			}
		}
	}

	stale := 0
	for _, p := range pins {
		var pinned *upspin.User
		var err error
		if p.anchor != "" {
			pinned, err = trust.ReadAnchor(dir, p.anchor, p.name)
		} else {
			pinned, err = trust.Read(dir, p.name)
		}
		if err != nil {
			s.Fail(err)
			continue
		}
		what := string(p.name)
		if p.anchor != "" {
			what += " (anchor for " + p.anchor + ")"
		}
		published := checker.Published(p.name)
		switch {
		case published == nil:
			s.Printf("%s\tnot published\n", what)
		case published.PublicKey == pinned.PublicKey:
			s.Printf("%s\tok\n", what)
		default:
			stale++
			s.Printf("%s\tSTALE\n\tpinned:    %s\n\tpublished: %s\n",
				what, factotum.Fingerprint(pinned.PublicKey), factotum.Fingerprint(published.PublicKey))
		}
	}
	if stale > 0 {
		s.Failf("%d pinned record(s) are out of date; replace each with "+
			"'upspin keytrust -remove <user>' then 'upspin keytrust -add <user>'", stale)
	}
}

// keytrustAdd pins one user record, or one trust anchor.
func (s *State) keytrustAdd(fs *flag.FlagSet, dir, inFile, fingerprint string, force, anchor bool, domain string) {
	if fingerprint != "" && force {
		s.Exitf("cannot use -fingerprint and -force together")
	}
	if !anchor && domain != "" {
		s.Exitf("-domain is only used with -anchor")
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
	// holder of the domain's trust anchor has already vouched for the
	// record. An anchor itself has nothing above it to vouch for it, so it
	// must always be verified directly.
	verified := false
	if attestation != nil && !anchor {
		if _, err := trust.Accept(dir, data); err != nil {
			s.Exitf("the attestation on this record was not accepted: %v", err)
		}
		verified = true
	}
	if !verified {
		if fingerprint == "" && !force {
			what := "pinning a key that has not been verified is pointless"
			if anchor {
				what = "a trust anchor vouches for a whole domain and must itself be verified"
			}
			s.Exitf("%s; use -fingerprint to verify it, or -force to pin it anyway", what)
		}
		if got := factotum.Fingerprint(u.PublicKey); fingerprint != "" && got != fingerprint {
			s.Exitf("fingerprint of the key for %s is %s, not %s; the key was NOT pinned", u.Name, got, fingerprint)
		}
	}

	if anchor {
		if domain == "" {
			if domain, err = domainOf(u.Name); err != nil {
				s.Exit(err)
			}
		}
		if err := trust.WriteAnchor(dir, domain, u); err != nil {
			s.Exit(err)
		}
		s.Printf("pinned %s as the trust anchor for %s %s\n", u.Name, domain, factotum.Fingerprint(u.PublicKey))
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

// keytrustRemove deletes pinned records or trust anchors.
func (s *State) keytrustRemove(fs *flag.FlagSet, dir string, anchor bool, domain string) {
	if domain != "" && !anchor {
		s.Exitf("-domain is only used with -anchor")
	}
	for i := 0; i < fs.NArg(); i++ {
		arg := fs.Arg(i)
		if anchor {
			// Without -domain the arguments name domains, and every
			// anchor for each goes. With it they name anchors
			// within that one domain, so that a domain with more
			// than one keeps the rest.
			if domain != "" {
				name := s.cleanUserName(arg)
				if err := trust.RemoveAnchor(dir, domain, name); err != nil {
					s.Fail(err)
					continue
				}
				s.Printf("removed %s as a trust anchor for %s\n", name, domain)
				continue
			}
			if err := trust.RemoveAnchors(dir, arg); err != nil {
				s.Fail(err)
				continue
			}
			s.Printf("removed the trust anchors for %s\n", arg)
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

// keytrustList prints the pinned users and trust anchors, or the complete
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

	domains, err := trust.ListAnchors(dir)
	if err != nil {
		s.Exit(err)
	}
	for _, domain := range domains {
		anchors, err := trust.ReadAnchors(dir, domain)
		if err != nil {
			s.Fail(err)
			continue
		}
		for _, u := range anchors {
			s.Printf("anchor for %s\t%s\t%s\n", domain, u.Name, factotum.Fingerprint(u.PublicKey))
		}
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
