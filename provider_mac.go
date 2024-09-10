//go:build darwin

package gssapi

/*
#cgo LDFLAGS: -L/usr/local/opt/heimdal/lib  -lgssapi
#cgo CPPFLAGS: -I/usr/local/opt/heimdal/include
*/
import "C"

