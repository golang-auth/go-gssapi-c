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
	case g.HasExtChannelBound:
		return C.has_channel_bound() == 1
	case g.HasExtLocalname:
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
