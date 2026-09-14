// Copyright 2016 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package provision

import (
	"bytes"
	"compress/zlib"
	"io"
	"strings"

	"upspin.io/errors"
)

// Compact form. A document is a few hundred bytes of text whose bulk is
// decimal digits, which compress well, and a QR code stores text drawn from
// the 45-character alphanumeric set in five and a half bits a character
// rather than eight. Compressing the document and writing it in that
// alphabet (base45, RFC 9285) makes the code about half the size, which is
// what lets it fit in an ordinary terminal window.

// CompactPrefix marks a document in compact form.
const CompactPrefix = "UPSPIN1:"

const base45Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"

// maxCompact bounds what Parse will inflate, so a hostile code cannot
// expand without limit. A document is a few kilobytes at most.
const maxCompact = 1 << 20

// Encode returns the document in compact form, for a QR code.
func (d *Document) Encode() (string, error) {
	const op errors.Op = "provision.Encode"
	data, err := d.Marshal()
	if err != nil {
		return "", errors.E(op, err)
	}
	return CompactPrefix + encodeCompact(data), nil
}

// encodeCompact compresses data and writes it in base45.
func encodeCompact(data []byte) string {
	var buf bytes.Buffer
	w, _ := zlib.NewWriterLevel(&buf, zlib.BestCompression)
	w.Write(data)
	w.Close()
	return base45Encode(buf.Bytes())
}

// decodeCompact returns the document text held by a compact form, its
// prefix already removed.
func decodeCompact(s string) ([]byte, error) {
	const op errors.Op = "provision.decodeCompact"
	raw, err := base45Decode(strings.TrimSpace(s))
	if err != nil {
		return nil, errors.E(op, errors.Invalid, err)
	}
	r, err := zlib.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, errors.E(op, errors.Invalid, err)
	}
	defer r.Close()
	data, err := io.ReadAll(io.LimitReader(r, maxCompact+1))
	if err != nil {
		return nil, errors.E(op, errors.Invalid, err)
	}
	if len(data) > maxCompact {
		return nil, errors.E(op, errors.Invalid, errors.Str("compact document is too large"))
	}
	return data, nil
}

// base45Encode writes each pair of bytes as three characters and a
// trailing single byte as two.
func base45Encode(b []byte) string {
	var s strings.Builder
	s.Grow((len(b) + 1) / 2 * 3)
	for len(b) >= 2 {
		n := int(b[0])<<8 | int(b[1])
		s.WriteByte(base45Alphabet[n%45])
		s.WriteByte(base45Alphabet[n/45%45])
		s.WriteByte(base45Alphabet[n/45/45])
		b = b[2:]
	}
	if len(b) == 1 {
		n := int(b[0])
		s.WriteByte(base45Alphabet[n%45])
		s.WriteByte(base45Alphabet[n/45])
	}
	return s.String()
}

func base45Decode(s string) ([]byte, error) {
	if len(s)%3 == 1 {
		return nil, errors.Errorf("base45: bad length %d", len(s))
	}
	b := make([]byte, 0, len(s)/3*2+1)
	value := func(c byte) (int, error) {
		i := strings.IndexByte(base45Alphabet, c)
		if i < 0 {
			return 0, errors.Errorf("base45: bad character %q", c)
		}
		return i, nil
	}
	for len(s) > 0 {
		var n int
		k := 3
		if len(s) == 2 {
			k = 2
		}
		for i := k - 1; i >= 0; i-- {
			v, err := value(s[i])
			if err != nil {
				return nil, err
			}
			n = n*45 + v
		}
		if k == 3 {
			if n > 0xffff {
				return nil, errors.Str("base45: value out of range")
			}
			b = append(b, byte(n>>8), byte(n))
		} else {
			if n > 0xff {
				return nil, errors.Str("base45: value out of range")
			}
			b = append(b, byte(n))
		}
		s = s[k:]
	}
	return b, nil
}
