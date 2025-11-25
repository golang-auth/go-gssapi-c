package gssapi

// SPDX-License-Identifier: Apache-2.0

import (
	"errors"

	g "github.com/golang-auth/go-gssapi/v3"
)

/*
#include "gss.h"
*/
import "C"

func (p *provider) IndicateMechs() ([]g.GssMech, error) {
	var minor C.OM_uint32
	var cMechSet C.gss_OID_set // Allocated by GSSAPI; freed by *1

	major := C.gss_indicate_mechs(&minor, &cMechSet)
	if major != C.GSS_S_COMPLETE {
		return nil, makeStatus(major, minor)
	}
	// *1 release GSSAPI allocated memory
	defer C.gss_release_oid_set(&minor, &cMechSet)

	ret := make([]g.GssMech, 0, cMechSet.count)
	mechOids := oidsFromGssOidSet(cMechSet)

	// Use unsafe to access the OID set elements
	for _, oid := range mechOids {
		mech, err := g.MechFromOid(oid)
		switch {
		default:
			ret = append(ret, mech)
		case errors.Is(err, g.ErrBadMech):
			// warn
			continue
		case err != nil:
			return nil, err
		}
		// If MechFromOid fails, skip that OID (could log or handle differently if desired)
	}
	return ret, nil
}
