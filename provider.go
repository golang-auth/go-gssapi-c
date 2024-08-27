package gssapi

import (
	"errors"

	g "github.com/golang-auth/go-gssapi/v3"
)

// #cgo LDFLAGS: -lgssapi_krb5
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

var ErrTooLarge = errors.New("The GSSAPI-C bindings only support up to 32 bit messages")
