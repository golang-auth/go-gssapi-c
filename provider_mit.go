//go:build !heimdal

package gssapi

// #cgo LDFLAGS: -lgssapi_krb5
import "C"
