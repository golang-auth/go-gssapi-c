// SPDX-License-Identifier: Apache-2.0

package gssapi

//#cgo !openbsd LDFLAGS: -ldl
/*
#include "gss.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"runtime"

	g "github.com/golang-auth/go-gssapi/v3"
)

type Credential struct {
	id C.gss_cred_id_t

	// store usage because FreeBSD base GSSAPI is broken and doesn't return the correct usage
	usage g.CredUsage

	isFromNoName bool
}

func hasDuplicateCred() bool {
	return hasSymbol("gss_duplicate_cred")
}

func (provider) AcquireCredential(name g.GssName, mechs []g.GssMech, usage g.CredUsage, lifetime *g.GssLifetime) (g.Credential, error) {
	// turn the mechs into an array of OIDs
	cOidSet, err := newOidSet(mechsToOids(mechs))
	if err != nil {
		return nil, err
	}
	defer cOidSet.Release() //nolint:errcheck

	var cGssName C.gss_name_t = C.GSS_C_NO_NAME
	if name != nil {
		lName, ok := name.(*GssName)
		if !ok {
			return nil, fmt.Errorf("bad name type %T, %w", name, g.ErrBadName)
		}

		cGssName = lName.name
	}

	var minor C.OM_uint32
	var cCredID C.gss_cred_id_t = C.GSS_C_NO_CREDENTIAL
	major := C.gss_acquire_cred(&minor, cGssName, gssLifetimeToSeconds(lifetime), cOidSet.oidSet, C.int(usage), &cCredID, nil, nil)

	if major != 0 {
		return nil, makeStatus(major, minor)
	}

	cred := &Credential{
		id:           cCredID,
		usage:        usage,
		isFromNoName: cGssName == C.GSS_C_NO_NAME,
	}

	return cred, nil
}

func (c *Credential) Release() error {
	if c == nil || c.id == nil {
		return nil
	}
	var minor C.OM_uint32
	major := C.gss_release_cred(&minor, &c.id)
	c.id = nil
	return makeStatus(major, minor)
}

func (c *Credential) Inquire() (*g.CredInfo, error) {
	var minor C.OM_uint32
	var cGssName C.gss_name_t // cGssName allocated by GSSAPI; releaseed by *1
	var cTimeRec C.OM_uint32
	var cCredUsage C.gss_cred_usage_t
	var cMechs C.gss_OID_set // cActualMechs.elements allocated by GSSAPI; released by *2
	major := C.gss_inquire_cred(&minor, c.id, &cGssName, &cTimeRec, &cCredUsage, &cMechs)

	if major != 0 {
		return nil, makeStatus(major, minor)
	}

	// *2  release GSSAPI allocated array
	defer C.gss_release_oid_set(&minor, &cMechs)

	// *1  release GSSAPI name
	gssName := nameFromGssInternal(cGssName)
	defer gssName.Release() //nolint:errcheck

	// We can't find any info about the name if the cred was acquired without a name on recent Heimdal versions.
	name, nameType := "", g.GssNameType(g.GSS_NO_NAME)
	if !(isHeimdalAfter7() && c.isFromNoName && c.usage == g.CredUsageAcceptOnly) {
		var err error
		name, nameType, err = gssName.Display()
		if err != nil {
			return nil, err
		}
	}

	var usage g.CredUsage = g.CredUsage(cCredUsage)
	if isHeimdalFreeBSD() {
		// FreeBSD gets it wrong.. use the value used to acquire the credential
		usage = c.usage
	}

	ret := &g.CredInfo{
		Name:     name,
		NameType: nameType,
		Usage:    usage,
	}

	switch ret.Usage {
	case g.CredUsageInitiateOnly:
		ret.InitiatorExpiry = timeRecToGssLifetime(cTimeRec)
	case g.CredUsageAcceptOnly:
		ret.AcceptorExpiry = timeRecToGssLifetime(cTimeRec)
	case g.CredUsageInitiateAndAccept:
		ret.InitiatorExpiry = timeRecToGssLifetime(cTimeRec)
		ret.AcceptorExpiry = timeRecToGssLifetime(cTimeRec)
	}

	actualMechOids := oidsFromGssOidSet(cMechs)
	for _, oid := range actualMechOids {
		mech, err := g.MechFromOid(oid)
		switch {
		default:
			ret.Mechs = append(ret.Mechs, mech)
		case errors.Is(err, g.ErrBadMech):
			// warn
			continue
		case err != nil:
			return nil, err
		}
	}

	return ret, nil
}

func (c *Credential) InquireByMech(mech g.GssMech) (*g.CredInfo, error) {
	cMechOid, pinner := oid2Coid(mech.Oid(), nil)
	defer pinner.Unpin()

	var minor C.OM_uint32
	var cGssName C.gss_name_t // cGssName allocated by GSSAPI; releaseed by *1
	var cTimeRecInit, cTimeRecAcc C.OM_uint32
	var cCredUsage C.gss_cred_usage_t
	major := C.gss_inquire_cred_by_mech(&minor, c.id, cMechOid, &cGssName, &cTimeRecInit, &cTimeRecAcc, &cCredUsage)

	if major != 0 {
		return nil, makeMechStatus(major, minor, mech)
	}

	gssName := nameFromGssInternal(cGssName)

	// *1  release GSSAPI name
	defer gssName.Release() //nolint:errcheck

	// We can't find any info about the name if the cred was acquired without a name on recent Heimdal versions.
	name, nameType := "", g.GssNameType(g.GSS_NO_NAME)
	if !(isHeimdalAfter7() && c.isFromNoName && c.usage == g.CredUsageAcceptOnly) {
		var err error
		name, nameType, err = gssName.Display()
		if err != nil {
			return nil, err
		}
	}

	var usage g.CredUsage = g.CredUsage(cCredUsage)
	if isHeimdalFreeBSD() {
		// FreeBSD gets it wrong.. use the value used to acquire the credential
		usage = c.usage

		if usage == g.CredUsageInitiateOnly {
			cTimeRecInit, cTimeRecAcc = cTimeRecAcc, cTimeRecInit
		}
	}

	ret := &g.CredInfo{
		Name:            name,
		NameType:        nameType,
		Usage:           usage,
		Mechs:           []g.GssMech{mech},
		InitiatorExpiry: timeRecToGssLifetime(cTimeRecInit),
		AcceptorExpiry:  timeRecToGssLifetime(cTimeRecAcc),
	}

	return ret, nil
}

func (c *Credential) Add(name g.GssName, mech g.GssMech, usage g.CredUsage, initiatorLifetime *g.GssLifetime, acceptorLifetime *g.GssLifetime, mutate bool) (g.Credential, error) {
	// old versions of Heimdal such as those in *BSD and Mac based systems have a
	// non-functional gss_add_cred implementation.
	if isHeimdal() && !isHeimdalWorkingAddCred() {
		err := makeCustomStatus(C.GSS_S_UNAVAILABLE, fmt.Errorf("gss_add_cred is not available when using this version of Heimdal"))
		return nil, err
	}

	var cMechOid C.gss_OID = C.GSS_C_NO_OID
	pinner := &runtime.Pinner{}
	if mech != nil {
		cMechOid, _ = oid2Coid(mech.Oid(), pinner)
	}

	var cGssName C.gss_name_t = C.GSS_C_NO_NAME
	if name != nil {
		lName, ok := name.(*GssName)
		if !ok {
			return nil, fmt.Errorf("bad name type %T, %w", name, g.ErrBadName)
		}

		cGssName = lName.name
	}

	var minor C.OM_uint32
	var cCredOut C.gss_cred_id_t = C.GSS_C_NO_CREDENTIAL
	var cpCredOut *C.gss_cred_id_t = nil
	if !mutate {
		cpCredOut = &cCredOut
	}

	major := C.gss_add_cred(&minor, c.id, cGssName, cMechOid, C.int(usage), gssLifetimeToSeconds(initiatorLifetime), gssLifetimeToSeconds(acceptorLifetime), cpCredOut, nil, nil, nil)
	if major != 0 {
		return nil, makeMechStatus(major, minor, mech)
	}

	if mutate {
		return c, nil
	} else {
		return &Credential{id: cCredOut}, nil
	}
}
