package gssapi

import (
	"runtime"

	g "github.com/golang-auth/go-gssapi/v3"
)

/*
#include "gss.h"
*/
import "C"

type oidSet struct {
	pinner *runtime.Pinner
	oidSet C.gss_OID_set
}

func newOidSet(oids []g.Oid) (*oidSet, error) {
	ret := &oidSet{
		pinner: &runtime.Pinner{},
		oidSet: nil,
	}

	if len(oids) == 0 {
		return ret, nil
	}

	var cMinor C.OM_uint32
	cMajor := C.gss_create_empty_oid_set(&cMinor, &ret.oidSet)
	if cMajor != C.GSS_S_COMPLETE {
		return nil, makeStatus(cMajor, cMinor)
	}

	for _, oid := range oids {
		cOid, _ := oid2Coid(oid, ret.pinner)
		cMajor := C.gss_add_oid_set_member(&cMinor, cOid, &ret.oidSet)
		if cMajor != C.GSS_S_COMPLETE {
			return nil, makeStatus(cMajor, cMinor)
		}
	}

	return ret, nil
}

func (o *oidSet) Release() error {
	if o == nil || o.oidSet == nil {
		return nil
	}

	var minor C.OM_uint32
	cMajor := C.gss_release_oid_set(&minor, &o.oidSet)
	if cMajor != C.GSS_S_COMPLETE {
		return makeStatus(cMajor, minor)
	}
	o.pinner.Unpin()
	return nil
}
