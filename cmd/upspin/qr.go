// Copyright 2026 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"os"
	"strings"

	"rsc.io/qr"

	"upspin.io/provision"
)

func (s *State) qr(args ...string) {
	const help = `
Qr shows, as a QR code on the terminal, everything another device
needs in order to act as this user: the user name, the directory and
store server endpoints, the packing, the key sets and discovery
setting, the key pair, and the trust anchors pinned in the keydir.
The Upspin app for Android installs itself from it.

The code contains the private key. Show it only on a screen you
trust, and only to a device you trust; anyone who scans it is you.

With -text, qr prints the provisioning document itself instead of a
code, which is what the code contains, compressed; with -compact, the
code's contents as one line of text, which the app also accepts
pasted; with -out, it writes the document to a file, for moving by
some other means. With
-pins, the pinned leaf records are included as well as the anchors,
which is rarely needed, since a device that has the anchors can accept
any attested record, and makes the code larger.

With -anchors, qr shows a different and smaller document: only the
trust anchors pinned in the keydir, for the domains named as arguments
or for every domain when none are, and no identity at all. It is for
a device that already has an identity and needs to be told whom to
believe about a domain. With -self, the document instead offers this
configuration's own user as the trust anchor for its own domain, or
for the domains named: this is how the owner of an anchor key hands
it out. Whoever scans it will believe every record it attests, so show
it in person; the app shows the fingerprint before pinning.

The code is drawn with block characters and its own colors, so it is
readable on a light or a dark terminal, but it must fit: a document of
usual size needs a window about 80 columns wide.
`
	fs := flag.NewFlagSet("qr", flag.ExitOnError)
	text := fs.Bool("text", false, "print the provisioning document instead of a code")
	compactFlag := fs.Bool("compact", false, "print the code's contents as one line of text, for pasting")
	out := fs.String("out", "", "write the provisioning document to `file` instead of showing a code")
	pins := fs.Bool("pins", false, "include the pinned leaf records, not only the trust anchors")
	anchors := fs.Bool("anchors", false, "show only the pinned trust anchors, for the domains named or all")
	self := fs.Bool("self", false, "offer this user as the trust anchor for its domain, or the domains named")
	s.ParseFlags(fs, args, help, "qr [-text | -compact | -out=file] [-pins]\n              qr [-text | -compact | -out=file] -anchors [domain...]\n              qr [-text | -compact | -out=file] -self [domain...]")
	if fs.NArg() != 0 && !*anchors && !*self {
		usageAndExit(fs)
	}
	if (*text && *out != "") || (*text && *compactFlag) || (*compactFlag && *out != "") {
		s.Exitf("-text, -compact and -out are exclusive")
	}
	if *pins && (*anchors || *self) {
		s.Exitf("-pins applies only to the identity document")
	}
	if *anchors && *self {
		s.Exitf("-anchors and -self are exclusive")
	}

	// Each kind of document has a plain form and a compact one.
	var data []byte
	var compact string
	var err error
	switch {
	case *anchors || *self:
		var t *provision.Trust
		if *self {
			t, err = provision.SelfTrust(s.Config, fs.Args()...)
		} else {
			t, err = provision.GatherTrust(s.Config, fs.Args()...)
		}
		if err != nil {
			s.Exit(err)
		}
		if data, err = t.Marshal(); err != nil {
			s.Exit(err)
		}
		if compact, err = t.Encode(); err != nil {
			s.Exit(err)
		}
		if !*text && !*compactFlag && *out == "" {
			s.Printf("%s", t.Describe())
		}
	default:
		doc, err := provision.Gather(s.Config, *pins)
		if err != nil {
			s.Exit(err)
		}
		if data, err = doc.Marshal(); err != nil {
			s.Exit(err)
		}
		if compact, err = doc.Encode(); err != nil {
			s.Exit(err)
		}
	}
	switch {
	case *out != "":
		if err := os.WriteFile(*out, data, 0600); err != nil {
			s.Exit(err)
		}
	case *text:
		s.Printf("%s", data)
	case *compactFlag:
		s.Printf("%s\n", compact)
	default:
		code, err := qr.Encode(compact, qr.L)
		if err != nil {
			s.Exitf("encoding %d characters as a QR code: %v", len(compact), err)
		}
		s.Printf("%s", renderQR(code))
		s.Printf("%d bytes as %d characters, %d modules a side; scan with the Upspin app.\n", len(data), len(compact), code.Size)
	}
}

// renderQR draws the code two modules per line with half-block characters,
// setting the colors explicitly so that the result does not depend on the
// terminal's own, with a quiet zone of two modules around it.
func renderQR(code *qr.Code) string {
	const (
		quiet  = 2
		colors = "\x1b[30;107m" // black on bright white
		reset  = "\x1b[0m"
	)
	black := func(x, y int) bool {
		return code.Black(x-quiet, y-quiet)
	}
	size := code.Size + 2*quiet
	var b strings.Builder
	for y := 0; y < size; y += 2 {
		b.WriteString(colors)
		for x := 0; x < size; x++ {
			top := black(x, y)
			bottom := y+1 < size && black(x, y+1)
			switch {
			case top && bottom:
				b.WriteString("█")
			case top:
				b.WriteString("▀")
			case bottom:
				b.WriteString("▄")
			default:
				b.WriteString(" ")
			}
		}
		b.WriteString(reset)
		b.WriteString("\n")
	}
	return b.String()
}
