// Package pgpmail implements PGP encryption for e-mail messages.
//
// PGP/MIME is defined in RFC 3156.
package pgpmail

import (
	"crypto"
)

// See RFC 4880, section 9.4.
var hashAlgs = map[string]crypto.Hash{
	"pgp-md5":       crypto.MD5,
	"pgp-sha1":      crypto.SHA1,
	"pgp-ripemd160": crypto.RIPEMD160,
	"pgp-sha256":    crypto.SHA256,
	"pgp-sha384":    crypto.SHA384,
	"pgp-sha512":    crypto.SHA512,
	"pgp-sha224":    crypto.SHA224,
}
