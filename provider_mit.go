//go:build !heimdal && !darwin

package gssapi

//#cgo pkg-config:mit-krb5-gssapi
import "C"
