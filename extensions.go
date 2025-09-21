//go:build !noextensions

// SPDX-License-Identifier: Apache-2.0

package gssapi

import (
	"unsafe"

	g "github.com/golang-auth/go-gssapi/v3"
)

/*
#include "gss.h"
*/
import "C"

func (p *provider) HasExtension(e g.GssapiExtension) bool {
	switch e {
	case g.GssapiExtHasChannelBound:
		return C.has_channel_bound() == 1
	case g.GssapiExtHasInquireName:
		return true
	default:
		// unknown extension
		return false
	}
}

func extractBufferSet(bs C.gss_buffer_set_t) [][]byte {
	out := make([][]byte, bs.count)

	bufSlice := unsafe.Slice(bs.elements, bs.count)
	for i, buf := range bufSlice {
		out[i] = C.GoBytes(buf.value, C.int(buf.length))
	}

	return out
}

func (n *GssName) Inquire() (bool, []string, error) {
	var minor C.OM_uint32
	var cNameIsMN C.int
	var cMech C.gss_OID = C.GSS_C_NO_OID
	var cAttrs C.gss_buffer_set_t // Freed by *1
	major := C.gss_inquire_name(&minor, n.name, &cNameIsMN, &cMech, &cAttrs)
	if major != 0 {
		return false, nil, makeStatus(major, minor)
	}

	// *1 Free buffers
	defer C.gss_release_buffer_set(&minor, &cAttrs)

	attrs := [][]byte{}
	if cAttrs != C.GSS_C_NO_BUFFER_SET {
		attrs = extractBufferSet(cAttrs)
	}

	outAttrs := make([]string, len(attrs))
	for i, v := range attrs {
		outAttrs[i] = string(v)
	}

	return cNameIsMN == 1, outAttrs, nil
}
