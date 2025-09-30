//go:build unix && !darwin && !freebsd

// SPDX-License-Identifier: Apache-2.0

package gssapi

//#cgo pkg-config:krb5-gssapi
import "C"
