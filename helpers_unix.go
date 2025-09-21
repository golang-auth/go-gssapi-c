//go:build !darwin && unix

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

func oidFromGssOid(cOid C.gss_OID) g.Oid {
	return C.GoBytes(cOid.elements, C.int(cOid.length))
}

func oid2Coid(oid g.Oid) C.gss_OID {
	if len(oid) > 0 {
		return &C.gss_OID_desc{
			length:   C.OM_uint32(len(oid)),
			elements: unsafe.Pointer(&oid[0]),
		}
	} else {
		return C.GSS_C_NO_OID
	}
}
