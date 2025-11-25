// SPDX-License-Identifier: Apache-2.0

package gssapi

/*
#include "gss.h"

// The function pointers below are set to the actual function pointers in the library
// by the init function using symbolMap.Apply()


OM_uint32 (*__gogssapi_localname)(OM_uint32 *minor, const gss_name_t name, gss_OID mech, gss_buffer_t output);

OM_uint32 (_gogssapi_localname)(OM_uint32 *minor, const gss_name_t name, gss_OID mech, gss_buffer_t output) {
	if( __gogssapi_localname == NULL ) {
		*minor = 0;
		return GSS_S_UNAVAILABLE;
	}
	return __gogssapi_localname(minor, name, mech, output);
}

OM_uint32 (*__gogssapi_inquire_name)(OM_uint32 *, const gss_name_t, int *, gss_OID *, gss_buffer_set_t *) = NULL;


OM_uint32 (_gogssapi_inquire_name)(OM_uint32 *minor, const gss_name_t name, int *name_is_MN, gss_OID *MN_mech, gss_buffer_set_t *attrs) {
	if( __gogssapi_inquire_name == NULL ) {
		*minor = 0;
		return GSS_S_UNAVAILABLE;
	}
	return __gogssapi_inquire_name(minor, name, name_is_MN, MN_mech, attrs);
}
*/
import "C"

import (
	g "github.com/golang-auth/go-gssapi/v3"
)

// Map optional symbols from the GSSAPI library to the wrapper function pointers
var namesSymbols = symbolMap{
	"gss_localname":    &C.__gogssapi_localname,
	"gss_inquire_name": &C.__gogssapi_inquire_name,
}

func init() {
	namesSymbols.Apply()
}

// Localname implements the GssNameExtLocalname extension.
func (n *GssName) Localname(mech g.GssMech) (string, error) {
	cMechOid, pinner := oid2Coid(mech.Oid(), nil)
	defer pinner.Unpin()

	var minor C.OM_uint32
	var cOutputBuf C.gss_buffer_desc = C.gss_empty_buffer // cOutputBuf.value allocated by GSSAPI; released by *1
	major := C._gogssapi_localname(&minor, n.name, cMechOid, &cOutputBuf)
	if major != C.GSS_S_COMPLETE {
		return "", makeStatus(major, minor)
	}

	// *1  release GSSAPI allocated buffer
	defer C.gss_release_buffer(&minor, &cOutputBuf)

	localname := C.GoStringN((*C.char)(cOutputBuf.value), C.int(cOutputBuf.length))

	return localname, nil
}

// Inquire implements part of the GssNameExtRFC6680 extension
func (n *GssName) Inquire() (g.InquireNameInfo, error) {
	ret := g.InquireNameInfo{
		Mech: g.GSS_NO_OID,
	}

	var minor C.OM_uint32
	var cNameIsMN C.int
	var cMech C.gss_OID = C.GSS_C_NO_OID
	var cAttrs C.gss_buffer_set_t // Freed by *1
	major := C._gogssapi_inquire_name(&minor, n.name, &cNameIsMN, &cMech, &cAttrs)
	if major != C.GSS_S_COMPLETE {
		return ret, makeStatus(major, minor)
	}

	// *1 Free buffers
	defer C.gss_release_buffer_set(&minor, &cAttrs)

	ret.IsMechName = cNameIsMN == 1
	if ret.IsMechName {
		oid := oidFromGssOid(cMech)
		nt, err := g.MechFromOid(oid)
		if err != nil {
			return ret, err
		}
		ret.Mech = nt
	}

	attrs := [][]byte{}
	if cAttrs != C.GSS_C_NO_BUFFER_SET {
		attrs = extractBufferSet(cAttrs)
	}

	ret.Attributes = make([]string, len(attrs))
	for i, v := range attrs {
		ret.Attributes[i] = string(v)
	}

	return ret, nil
}
