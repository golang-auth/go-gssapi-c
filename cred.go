// SPDX-License-Identifier: Apache-2.0

package gssapi

/*
#include "gssapi.h"

*/
import "C"

import (
	"errors"
	"fmt"
	"time"

	g "github.com/golang-auth/go-gssapi/v3"
)

type Credential struct {
	id C.gss_cred_id_t
}

func (provider) AcquireCredential(name g.GssName, mechs []g.GssMech, usage g.CredUsage, lifetime time.Duration) (g.Credential, error) {
	// turn the mechs into an array of OIDs
	gssOidSet := gssOidSetFromOids(mechsToOids(mechs))
	gssOidSet.Pin()
	defer gssOidSet.Unpin()

	var cGssName C.gss_name_t
	if name != nil {
		lName, ok := name.(*GssName)
		if !ok {
			return nil, fmt.Errorf("bad name type %T, %w", name, g.ErrBadName)
		}

		cGssName = lName.name
	}

	var minor C.OM_uint32
	var cCredId C.gss_cred_id_t
	major := C.gss_acquire_cred(&minor, cGssName, C.OM_uint32(lifetime.Seconds()), gssOidSet.oidSet, C.int(usage), &cCredId, nil, nil)

	if major != 0 {
		return nil, makeStatus(major, minor)
	}

	cred := &Credential{
		id: cCredId,
	}

	return cred, nil
}

func (c *Credential) Release() error {
	if c.id == nil {
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

	gssName := nameFromGssInternal(cGssName)

	// *1  release GSSAPI name
	defer gssName.Release() //nolint:all

	name, nameType, err := gssName.Display()
	if err != nil {
		return nil, err
	}

	ret := &g.CredInfo{
		Name:     name,
		NameType: nameType,
		Usage:    g.CredUsage(cCredUsage),
	}

	if cTimeRec != C.GSS_C_INDEFINITE {
		var t time.Time
		if cTimeRec != 0 {
			t = time.Now().Add(time.Second * time.Duration(cTimeRec)).Round(time.Second)
		}
		switch ret.Usage {
		default:
			ret.AcceptorExpiry = &t
			ret.InitiatorExpiry = &t
		case g.CredUsageAcceptOnly:
			ret.AcceptorExpiry = &t
		case g.CredUsageInitiateOnly:
			ret.InitiatorExpiry = &t
		}
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
	cMechOid := oid2Coid(mech.Oid())

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
	defer gssName.Release() //nolint:all

	name, nameType, err := gssName.Display()
	if err != nil {
		return nil, err
	}

	ret := &g.CredInfo{
		Name:     name,
		NameType: nameType,
		Usage:    g.CredUsage(cCredUsage),
		Mechs:    []g.GssMech{mech},
	}

	if cTimeRecInit != C.GSS_C_INDEFINITE {
		var t time.Time
		if cTimeRecInit != 0 {
			t = time.Now().Add(time.Second * time.Duration(cTimeRecInit)).Round(time.Second)
		}
		ret.InitiatorExpiry = &t
	}
	if cTimeRecAcc != C.GSS_C_INDEFINITE {
		var t time.Time
		if cTimeRecAcc != 0 {
			t = time.Now().Add(time.Second * time.Duration(cTimeRecAcc)).Round(time.Second)
		}
		ret.AcceptorExpiry = &t
	}

	return ret, nil
}

func (c *Credential) Add(name g.GssName, mech g.GssMech, usage g.CredUsage, initiatorLifetime time.Duration, acceptorLifetime time.Duration) error {
	cMechOid := oid2Coid(mech.Oid())

	var cGssName C.gss_name_t
	if name != nil {
		lName, ok := name.(*GssName)
		if !ok {
			return fmt.Errorf("bad name type %T, %w", name, g.ErrBadName)
		}

		cGssName = lName.name
	}

	var minor C.OM_uint32
	var cTimeRecInit, cTimeRecAcc C.OM_uint32
	var cActualMechs C.gss_OID_set // cActualMechs.elements allocated by GSSAPI; released by *1

	var cCredOut *C.gss_cred_id_t
	if isHeimdal() {
		var newCred C.gss_cred_id_t
		cCredOut = &newCred
	}

	major := C.gss_add_cred(&minor, c.id, cGssName, cMechOid, C.int(usage), C.OM_uint32(initiatorLifetime.Seconds()), C.OM_uint32(acceptorLifetime.Seconds()), cCredOut, &cActualMechs, &cTimeRecInit, &cTimeRecAcc)
	if major != 0 {
		return makeMechStatus(major, minor, mech)
	}

	var err error
	if isHeimdal() {
		err = c.Release()
		c.id = *cCredOut
	}

	return err
}
