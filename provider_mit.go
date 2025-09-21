//go:build !heimdal && !darwin

// SPDX-License-Identifier: Apache-2.0

package gssapi

//#cgo pkg-config:mit-krb5-gssapi
import "C"
