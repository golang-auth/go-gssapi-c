//go:build freebsd

// SPDX-License-Identifier: Apache-2.0

package gssapi

//#cgo !usepkgconfig,!fbsdmit LDFLAGS: -lgssapi -lgssapi_krb5
//#cgo fbsdmit LDFLAGS: -lgssapi_krb5
//#cgo usepkgconfig pkg-config:krb5-gssapi,krb5
import "C"
