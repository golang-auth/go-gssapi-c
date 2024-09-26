//go:build heimdal && !darwin

package gssapi

// #cgo CPPFLAGS: -I/usr/include/heimdal
// #cgo LDFLAGS: -L/usr/lib64/heimdal/lib -L/usr/lib/heimdal/lib -lgssapi
import "C"
