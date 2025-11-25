//go:build !darwin && unix

// SPDX-License-Identifier: Apache-2.0

package gssapi

import (
	"runtime"
	"unsafe"

	g "github.com/golang-auth/go-gssapi/v3"
)

/*
#include "gss.h"
*/
import "C"

func oidFromGssOid(cOid C.gss_OID) g.Oid {
	if cOid == C.GSS_C_NO_OID {
		return nil
	}

	return C.GoBytes(cOid.elements, C.int(cOid.length))
}

// oid2Coid returns a GSS OID structure containing the binary representation
// of the supplied OID, pinned in memory so that it can be passed to C without
// causing a panic.  The memory should be unpinned when the C layer is done with
// it using pinner.Unpin().
func oid2Coid(oid g.Oid, pinner *runtime.Pinner) (C.gss_OID, *runtime.Pinner) {
	if pinner == nil {
		pinner = &runtime.Pinner{}
	}

	if oid != nil && len(oid) > 0 {
		p := unsafe.Pointer(&oid[0])
		pinner.Pin(&oid[0])

		return &C.gss_OID_desc{
			length:   C.OM_uint32(len(oid)),
			elements: p,
		}, pinner
	} else {
		return C.GSS_C_NO_OID, pinner
	}
}
