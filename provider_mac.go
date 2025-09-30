//go:build darwin

// SPDX-License-Identifier: Apache-2.0

package gssapi

//#cgo !usepkgconfig CFLAGS: -DOSX_HAS_GSS_FRAMEWORK
//#cgo !usepkgconfig LDFLAGS: -framework GSS
//#cgo usepkgconfig pkg-config:krb5-gssapi,krb5
import "C"
