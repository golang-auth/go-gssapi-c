// SPDX-License-Identifier: Apache-2.0

// Package gssapi is a Go GSSAPI provides using the C bindings defined in RFC 2744.
package gssapi

import (
	"errors"
	"runtime"

	g "github.com/golang-auth/go-gssapi/v3"
)

/*
#include "gss.h"
#include <dlfcn.h>
*/
import "C"

// LIBID is the string that go-gssapi-c registers itself as a go-gssapi provier.
const LIBID = "github.com/golang-auth/go-gssapi-c"

func init() {
	g.RegisterProvider(LIBID, New)
}

type provider struct {
	name string
}

func New() (g.Provider, error) {
	return &provider{
		name: LIBID,
	}, nil
}

func (p *provider) Release() error {
	return nil
}

func (p provider) Name() string {
	return LIBID
}

// ErrTooLarge indicates that the caller tried to operate on a m.  The C bindings
// support a maximum 32-bit message.
var ErrTooLarge = errors.New("the GSSAPI-C bindings only support up to 32 bit messages")

func isHeimdal() bool {
	return C.IS_HEIMDAL == 1
}

func isHeimdalBefore7() bool {
	// gss_unwrap_aead appeared in Heimdal 7.0.1
	// gss_compare_name seems to work more intuitively from that release.
	return isHeimdal() && !hasSymbol("gss_unwrap_aead")
}

func isHeimdalAfter7() bool {
	return isHeimdal() && hasSymbol("gss_unwrap_aead")
}

func isHeimdalWorkingAddCred() bool {
	// gss_duplicate_cred appeared in commit e6d1c10808b (unreleased)
	// this commit introduced the rewrite of gss_add_cred which was basically
	// unusable before then.
	return isHeimdal() && hasSymbol("gss_duplicate_cred")
}

func hasChannelBound() bool {
	return C.has_channel_bound() == 1
}

// Is this Mac Kerberos?
func isMacGssapi() bool {
	return C.is_mac_framework() == 1
}

// Is this the ancient Heimdal that is part of the FreeBSD base system
// before FreeBSD 15?
func isHeimdalFreeBSD() bool {
	return isHeimdalBefore7() && runtime.GOOS == "freebsd"
}

func (p *provider) HasExtension(e g.GssapiExtension) bool {
	switch e {
	default:
		// unknown extension
		return false
	case g.HasExtChannelBindingSignalling:
		return hasChannelBound()
	case g.HasExtLocalname:
		return hasSymbol("gss_localname")
	case g.HasExtKrb5Identity:
		// It is not feasible to support gsskrb5_register_acceptor_identity / krb5_cc_set_default_name
		// because they set thread local values which cannot work with Go which moves its goroutines to
		// different threads.
		return false
	case g.HasExtCredStore:
		return hasSymbol("gss_acquire_cred_from") && hasSymbol("gss_store_cred_into") && hasSymbol("gss_add_cred_from")
	}
}
