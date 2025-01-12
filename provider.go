package gssapi

import (
	"errors"

	g "github.com/golang-auth/go-gssapi/v3"
)

/*
#include "gss.h"
*/
import "C"

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

var ErrTooLarge = errors.New("the GSSAPI-C bindings only support up to 32 bit messages")

func IsHeimdal() bool {
	return C.IS_HEIMDAL == 1
}

func HasChannelBound() bool {
	return C.has_channel_bound() == 1
}
