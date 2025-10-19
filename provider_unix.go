//go:build unix && !darwin && !freebsd && !openbsd

// SPDX-License-Identifier: Apache-2.0

package gssapi

//#cgo pkg-config:krb5-gssapi
import "C"
