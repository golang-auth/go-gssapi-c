//go:build darwin

// SPDX-License-Identifier: Apache-2.0

package gssapi

import (
	"runtime"
	"unsafe"

	g "github.com/golang-auth/go-gssapi/v3"
)

/*
#include "gss.h"

// work around Go not understanding packed structs
void _set_oid_fields(gss_OID oid, OM_uint32 len, void *elements) {
	oid->length = len;
	oid->elements = elements;
}

void *_get_oid_elements(gss_OID oid) {
	return oid->elements;
}
*/
import "C"

func oidFromGssOid(cOid C.gss_OID) g.Oid {
	if cOid == C.GSS_C_NO_OID {
		return nil
	}
	// Go doesn't know about the elements field of the gss_OID_desc struct
	// because it doesn't support packed structs.  The elements field is
	// 32 bits into the struct (after the length field)
	elms := C._get_oid_elements(cOid)
	return C.GoBytes(elms, C.int(cOid.length))
}

func oid2Coid(oid g.Oid, pinner *runtime.Pinner) (C.gss_OID, *runtime.Pinner) {
	if pinner == nil {
		pinner = &runtime.Pinner{}
	}

	if len(oid) > 0 {
		pinner.Pin(&oid[0])
		var cOid C.gss_OID_desc

		// Go doesn't know about the elements field of the gss_OID_desc struct due to alignment issues
		C._set_oid_fields(&cOid, C.OM_uint32(len(oid)), unsafe.Pointer(&oid[0]))
		return &cOid, pinner
	} else {
		return C.GSS_C_NO_OID, pinner
	}
}
