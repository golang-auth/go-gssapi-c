//go:build !noextensions

package gssapi

/*
#include "gss.h"
*/
import "C"
import "unsafe"

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
