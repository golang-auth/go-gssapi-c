// SPDX-License-Identifier: Apache-2.0

package gssapi

import (
	"errors"

	g "github.com/golang-auth/go-gssapi/v3"
)

/*
#include "gss.h"
*/
import "C"

// go-gssapi-c registers itself as a go-gssapi provier using this identifier.
const LIBID = "GSSAPI-C"

func init() {
	g.RegisterProvider(LIBID, New)
}

type provider struct {
	name string
}

func New() g.Provider {
	return &provider{
		name: LIBID,
	}
}

// ErrTooLarge indicates that the caller tried to operate on a m.  The C bindings
// support a maximum 32-bit message.
var ErrTooLarge = errors.New("the GSSAPI-C bindings only support up to 32 bit messages")

func isHeimdal() bool {
	return C.IS_HEIMDAL == 1
}
