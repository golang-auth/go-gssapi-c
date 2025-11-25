// SPDX-License-Identifier: Apache-2.0

//go:build unix && !darwin && !freebsd && !openbsd

package gssapi

//#cgo pkg-config:krb5-gssapi,krb5
import "C"
