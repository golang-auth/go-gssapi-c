//go:build !heimdal && !darwin

package gssapi

// #cgo LDFLAGS: -lgssapi_krb5
import "C"
