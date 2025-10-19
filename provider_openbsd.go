//go:build openbsd

// SPDX-License-Identifier: Apache-2.0

package gssapi

//#cgo !usepkgconfig CFLAGS: -I/usr/local/heimdal/include
//#cgo !usepkgconfig LDFLAGS: -L/usr/local/heimdal/lib -lgssapi
//#cgo usepkgconfig pkg-config:krb5-gssapi,krb5
import "C"
