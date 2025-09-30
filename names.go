// SPDX-License-Identifier: Apache-2.0

package gssapi

/*
#include "gss.h"
*/
import "C"

import (
	"errors"
	"fmt"

	g "github.com/golang-auth/go-gssapi/v3"
)

type GssName struct {
	name C.gss_name_t

	isFromNoName bool
}

func nameFromGssInternal(name C.gss_name_t) *GssName {
	return &GssName{name, false}
}

func (provider) ImportName(name string, nameType g.GssNameType) (g.GssName, error) {
	cNameOid := oid2Coid(nameType.Oid())

	cNameBuf, pinner := bytesToCBuffer([]byte(name))
	defer pinner.Unpin()

	var minor C.OM_uint32
	var cGssName C.gss_name_t = C.GSS_C_NO_NAME
	major := C.gss_import_name(&minor, &cNameBuf, cNameOid, &cGssName)

	if major != C.GSS_S_COMPLETE {
		return nil, makeStatus(major, minor)
	}

	return &GssName{
		name:         cGssName,
		isFromNoName: false,
	}, nil
}

func (provider) InquireNamesForMech(mech g.GssMech) ([]g.GssNameType, error) {
	cMechOid := oid2Coid(mech.Oid())

	var minor C.OM_uint32
	var cNameTypes C.gss_OID_set = C.GSS_C_NO_OID_SET // cNameTypes.elements allocated by GSSAPI; released by *1
	major := C.gss_inquire_names_for_mech(&minor, cMechOid, &cNameTypes)

	if major != C.GSS_S_COMPLETE {
		return nil, makeStatus(major, minor)
	}

	defer C.gss_release_oid_set(&minor, &cNameTypes)

	nameTypeOids := oidsFromGssOidSet(cNameTypes)
	ret := make([]g.GssNameType, 0, len(nameTypeOids))

	seen := make(map[string]bool)

	for _, oid := range nameTypeOids {
		nt, err := g.NameTypeFromOid(oid)
		switch {
		default:
			ntStr := nt.String()
			if _, ok := seen[ntStr]; !ok {
				ret = append(ret, nt)
				seen[nt.String()] = true
			}
		case errors.Is(err, g.ErrBadNameType):
			// warn
			continue
		case err != nil:
			return nil, err
		}
	}

	return ret, nil
}

func (n *GssName) Compare(other g.GssName) (bool, error) {
	// other must be our type, not one from a different GSSAPI impl
	// .. but this method needs to implement gsscommon.GssName.Compare()
	otherName, ok := other.(*GssName)
	if !ok {
		return false, fmt.Errorf("can't compare %T with %T: %w", n, other, g.ErrBadName)
	}

	if n.isFromNoName && isHeimdalAfter7() {
		return false, makeCustomStatus(C.GSS_S_UNAVAILABLE, fmt.Errorf("gss_compare_name on this name is not stable on this version of Heimdal"))
	}

	var minor C.OM_uint32
	var cEqual C.int
	major := C.gss_compare_name(&minor, n.name, otherName.name, &cEqual)
	if major != C.GSS_S_COMPLETE {
		return false, makeStatus(major, minor)
	}

	return cEqual != 0, nil
}

func (n *GssName) Display() (string, g.GssNameType, error) {
	if n.isFromNoName && isHeimdalAfter7() {
		return "", g.GSS_NO_OID, makeCustomStatus(C.GSS_S_UNAVAILABLE, fmt.Errorf("gss_display_name on this name is not stable on this version of Heimdal"))
	}

	var minor C.OM_uint32
	var cOutputBuf C.gss_buffer_desc = C.gss_empty_buffer // outputBuf.value allocated by GSSAPI; released by *1
	var cOutType C.gss_OID = C.GSS_C_NO_OID               // not to be freed (static GSSAPI data)
	major := C.gss_display_name(&minor, n.name, &cOutputBuf, &cOutType)
	if major != C.GSS_S_COMPLETE {
		return "", g.GSS_NO_OID, makeStatus(major, minor)
	}

	// *1 release GSSAPI allocated buffer
	defer C.gss_release_buffer(&minor, &cOutputBuf)

	name := C.GoBytes(cOutputBuf.value, C.int(cOutputBuf.length))

	oid := oidFromGssOid(cOutType)
	nameType, err := g.NameTypeFromOid(oid)
	if err != nil {
		return "", g.GSS_NO_OID, makeStatus(major, minor)
	}

	return string(name), nameType, nil
}

func (n *GssName) Release() error {
	if n.name == C.GSS_C_NO_NAME {
		return nil
	}
	var minor C.OM_uint32
	major := C.gss_release_name(&minor, &n.name)
	n.name = nil
	return makeStatus(major, minor)
}

func (n *GssName) InquireMechs() ([]g.GssMech, error) {
	var minor C.OM_uint32
	var cMechSet C.gss_OID_set = C.GSS_C_NO_OID_SET // cMechSet.elements allocated by GSSAPI; released by *1
	major := C.gss_inquire_mechs_for_name(&minor, n.name, &cMechSet)
	if major != 0 {
		return nil, makeStatus(major, minor)
	}

	// *1   release GSSAPI allocated array
	defer C.gss_release_oid_set(&minor, &cMechSet)

	ret := make([]g.GssMech, 0, cMechSet.count)
	mechOids := oidsFromGssOidSet(cMechSet)

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
	}

	return ret, nil
}

func (n *GssName) Canonicalize(mech g.GssMech) (g.GssName, error) {
	if n.isFromNoName && isHeimdalAfter7() {
		return nil, makeCustomStatus(C.GSS_S_UNAVAILABLE, fmt.Errorf("gss_display_name on this name is not stable on this version of Heimdal"))
	}

	cMechOid := oid2Coid(mech.Oid())

	var minor C.OM_uint32
	var cOutName C.gss_name_t = C.GSS_C_NO_NAME
	major := C.gss_canonicalize_name(&minor, n.name, cMechOid, &cOutName)
	if major != 0 {
		return nil, makeMechStatus(major, minor, mech)
	}

	return &GssName{
		name: cOutName,
	}, nil
}

func (n *GssName) Export() ([]byte, error) {
	if n.isFromNoName && isHeimdalAfter7() {
		return nil, makeCustomStatus(C.GSS_S_UNAVAILABLE, fmt.Errorf("gss_display_name on this name is not stable on this version of Heimdal"))
	}

	var minor C.OM_uint32
	var cOutputBuf C.gss_buffer_desc = C.gss_empty_buffer // cOutputBuf.value allocated by GSSAPI; released by *1
	major := C.gss_export_name(&minor, n.name, &cOutputBuf)
	if major != C.GSS_S_COMPLETE {
		return nil, makeStatus(major, minor)
	}

	// *1  release GSSAPI allocated buffer
	defer C.gss_release_buffer(&minor, &cOutputBuf)

	exported := C.GoBytes(cOutputBuf.value, C.int(cOutputBuf.length))

	return exported, nil
}

func (n *GssName) Duplicate() (g.GssName, error) {
	if n.isFromNoName && isHeimdalAfter7() {
		return nil, makeCustomStatus(C.GSS_S_UNAVAILABLE, fmt.Errorf("gss_display_name on this name is not stable on this version of Heimdal"))
	}

	var minor C.OM_uint32
	var cOutName C.gss_name_t = C.GSS_C_NO_NAME
	major := C.gss_duplicate_name(&minor, n.name, &cOutName)
	if major != C.GSS_S_COMPLETE {
		return nil, makeStatus(major, minor)
	}

	return &GssName{
		name: cOutName,
	}, nil
}
