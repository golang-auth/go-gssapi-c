// SPDX-License-Identifier: Apache-2.0

package gssapi

/*
#include "gss.h"
#include <stdio.h>

#if ! defined(GSS_C_NO_CRED_STORE)
    struct gss_key_value_element_struct {
        const char *key;
        const char *value;
    };
    typedef struct gss_key_value_element_struct gss_key_value_element_desc;

    struct gss_key_value_set_struct {
        OM_uint32 count;
        gss_key_value_element_desc *elements;
    };
    typedef const struct gss_key_value_set_struct gss_key_value_set_desc;
    typedef const gss_key_value_set_desc *gss_const_key_value_set_t;
#endif

OM_uint32 (*__gss_acquire_cred_from)(OM_uint32 *minor_status,
								const gss_name_t desired_name,
								OM_uint32 time_req,
								const gss_OID_set desired_mechs,
								gss_cred_usage_t cred_usage,
								gss_const_key_value_set_t cred_store,
								gss_cred_id_t *output_cred_handle,
								gss_OID_set *actual_mechs,
								OM_uint32 *time_rec) = NULL;
OM_uint32 _gss_acquire_cred_from(OM_uint32 *minor_status,
								const gss_name_t desired_name,
								OM_uint32 time_req,
								const gss_OID_set desired_mechs,
								gss_cred_usage_t cred_usage,
								gss_const_key_value_set_t cred_store,
								gss_cred_id_t *output_cred_handle,
								gss_OID_set *actual_mechs,
								OM_uint32 *time_rec) {
	if( __gss_acquire_cred_from == NULL ) {
		*minor_status = 0;
		return GSS_S_UNAVAILABLE;
	}
	return __gss_acquire_cred_from(minor_status, desired_name, time_req, desired_mechs, cred_usage, cred_store, output_cred_handle, actual_mechs, time_rec);
}

OM_uint32 (*__gss_store_cred_into)(OM_uint32 *minor_status,
                                  gss_cred_id_t input_cred_handle,
                                  gss_cred_usage_t cred_usage,
                                  const gss_OID desired_mech,
                                  OM_uint32 overwrite_cred,
                                  OM_uint32 default_cred,
                                  gss_const_key_value_set_t cred_store,
                                  gss_OID_set *elements_stored,
                                  gss_cred_usage_t *cred_usage_stored) = NULL;

OM_uint32 _gss_store_cred_into(OM_uint32 *minor_status,
                                  gss_cred_id_t input_cred_handle,
                                  gss_cred_usage_t cred_usage,
                                  const gss_OID desired_mech,
                                  OM_uint32 overwrite_cred,
                                  OM_uint32 default_cred,
                                  gss_const_key_value_set_t cred_store,
                                  gss_OID_set *elements_stored,
                                  gss_cred_usage_t *cred_usage_stored)
								  {
	if( __gss_store_cred_into == NULL ) {
	*minor_status = 0;
	return GSS_S_UNAVAILABLE;
	}
	return __gss_store_cred_into(minor_status, input_cred_handle, cred_usage, desired_mech, overwrite_cred, default_cred, cred_store, elements_stored, cred_usage_stored);
}

OM_uint32 (*__gss_add_cred_from)(OM_uint32 *minor_status,
            gss_cred_id_t input_cred_handle,
            gss_name_t desired_name,
            gss_OID desired_mech,
            gss_cred_usage_t cred_usage,
            OM_uint32 initiator_time_req,
            OM_uint32 acceptor_time_req,
            gss_const_key_value_set_t cred_store,
            gss_cred_id_t *output_cred_handle,
            gss_OID_set *actual_mechs,
            OM_uint32 *initiator_time_rec,
            OM_uint32 *acceptor_time_rec) = NULL;

OM_uint32 _gss_add_cred_from (OM_uint32 *minor_status,
            gss_cred_id_t input_cred_handle,
            gss_name_t desired_name,
            gss_OID desired_mech,
            gss_cred_usage_t cred_usage,
            OM_uint32 initiator_time_req,
            OM_uint32 acceptor_time_req,
            gss_const_key_value_set_t cred_store,
            gss_cred_id_t *output_cred_handle,
            gss_OID_set *actual_mechs,
            OM_uint32 *initiator_time_rec,
            OM_uint32 *acceptor_time_rec) {
	if( __gss_add_cred_from == NULL ) {
		*minor_status = 0;
		return GSS_S_UNAVAILABLE;
	}
	return __gss_add_cred_from(minor_status, input_cred_handle, desired_name, desired_mech, cred_usage, initiator_time_req, acceptor_time_req, cred_store, output_cred_handle, actual_mechs, initiator_time_rec, acceptor_time_rec);
}
*/
import "C"

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	g "github.com/golang-auth/go-gssapi/v3"
)

// Map optional symbols from the GSSAPI library to the wrapper function pointers
var credStoreSymbols = symbolMap{
	"gss_acquire_cred_from": &C.__gss_acquire_cred_from,
	"gss_store_cred_into":   &C.__gss_store_cred_into,
}

func init() {
	credStoreSymbols.Apply()
}

type credStore map[int]string

func newCredStore() credStore {
	return make(credStore)
}

func (s *credStore) SetOption(option int, value string) error {
	(*s)[option] = value
	return nil
}

func (s credStore) GetOption(option int) (string, bool) {
	value, ok := s[option]
	return value, ok
}

type kvset struct {
	kvset  C.gss_const_key_value_set_t
	pinner *runtime.Pinner
}

func (s credStore) kv() *kvset {
	kvs := kvset{
		kvset: &C.gss_key_value_set_desc{
			count:    0,
			elements: nil,
		},
		pinner: &runtime.Pinner{},
	}

	elms := make([]C.struct_gss_key_value_element_struct, 0, len(s))
	for opt, value := range s {
		elm := C.gss_key_value_element_desc{
			value: C.CString(value),
		}
		switch opt {
		default:
			continue
		case int(g.CredStoreCCache):
			elm.key = C.CString("ccache")
		case int(g.CredStoreClientKeytab):
			elm.key = C.CString("client_keytab")
		case int(g.CredStoreServerKeytab):
			elm.key = C.CString("keytab")
		case int(g.CredStorePassword):
			elm.key = C.CString("password")
		case int(g.CredStoreRCache):
			elm.key = C.CString("rcache")
		case int(g.CredStoreVerify):
			elm.key = C.CString("verify")
		}

		elms = append(elms, elm)
	}

	if len(elms) > 0 {
		kvs.kvset.elements = unsafe.SliceData(elms)
		kvs.kvset.count = C.OM_uint32(len(elms))

		kvs.pinner.Pin(kvs.kvset.elements)
	}

	return &kvs
}

func (k *kvset) Release() {
	for i := 0; i < int(k.kvset.count); i++ {
		elm := k.Get(i)
		if elm == nil {
			continue
		}
		C.free(unsafe.Pointer(elm.key))
		C.free(unsafe.Pointer(elm.value))
	}

	k.pinner.Unpin()
}

func (k *kvset) Get(idx int) *C.struct_gss_key_value_element_struct {
	if idx >= int(k.kvset.count) {
		return nil
	}
	usp := unsafe.Pointer(k.kvset.elements)
	usp = unsafe.Pointer(uintptr(usp) + uintptr(idx)*unsafe.Sizeof(C.struct_gss_key_value_element_struct{}))
	return (*C.struct_gss_key_value_element_struct)(usp)
}

func (k *kvset) kv(idx int) (string, string) {
	item := k.Get(idx)
	if item == nil {
		return "", ""
	}
	key := C.GoString(item.key)
	value := C.GoString(item.value)
	return key, value
}

// AcquireCredentialFrom implements part of the GssapiExtensionCredStore extension.
func (provider) AcquireCredentialFrom(name g.GssName, mechs []g.GssMech, usage g.CredUsage, lifetime *g.GssLifetime, opts ...g.CredStoreOption) (g.Credential, error) {
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

	credStore := newCredStore()
	for _, opt := range opts {
		if err := opt(&credStore); err != nil {
			return nil, err
		}
	}

	kv := credStore.kv()
	defer kv.Release()

	var cMinor C.OM_uint32
	var cCredID C.gss_cred_id_t = C.GSS_C_NO_CREDENTIAL
	cMajor := C._gss_acquire_cred_from(&cMinor, cGssName, gssLifetimeToSeconds(lifetime), cOidSet.oidSet, C.int(usage), kv.kvset, &cCredID, nil, nil)

	if cMajor != C.GSS_S_COMPLETE {
		return nil, makeStatus(cMajor, cMinor)
	}

	cred := &Credential{
		id:           cCredID,
		usage:        usage,
		isFromNoName: cGssName == C.GSS_C_NO_NAME,
	}

	return cred, nil
}

func (c *Credential) StoreInto(mech g.GssMech, usage g.CredUsage, overwrite bool, defaultCred bool, opts ...g.CredStoreOption) (mechsStored []g.GssMech, usageStored g.CredUsage, err error) {
	mechOid := g.Oid{}
	if mech != nil {
		mechOid = mech.Oid()
	}

	credStore := newCredStore()
	for _, opt := range opts {
		if err := opt(&credStore); err != nil {
			return nil, 0, err
		}
	}

	kv := credStore.kv()
	defer kv.Release()

	var cMinor C.OM_uint32
	var cOverwrite, cDefaultCred C.OM_uint32
	var cUsageStored C.gss_cred_usage_t
	var cElementsStored C.gss_OID_set
	if overwrite {
		cOverwrite = 1
	}
	if defaultCred {
		cDefaultCred = 1
	}
	cMechOid, pinner := oid2Coid(mechOid, nil)
	defer pinner.Unpin()

	cMajor := C._gss_store_cred_into(&cMinor, c.id, C.int(usage), cMechOid, cOverwrite, cDefaultCred, kv.kvset, &cElementsStored, &cUsageStored)

	if cMajor != C.GSS_S_COMPLETE {
		return nil, 0, makeStatus(cMajor, cMinor)
	}

	mechs := make([]g.GssMech, 0, cElementsStored.count)
	mechOids := oidsFromGssOidSet(cElementsStored)
	for _, oid := range mechOids {
		mech, err := g.MechFromOid(oid)
		switch {
		default:
			mechs = append(mechs, mech)
		case errors.Is(err, g.ErrBadMech):
			// warn
			continue
		case err != nil:
			return nil, 0, err
		}
		// If MechFromOid fails, skip that OID (could log or handle differently if desired)
	}

	return mechs, g.CredUsage(cUsageStored), nil
}

func (c *Credential) AddFrom(name g.GssName, mech g.GssMech, usage g.CredUsage, initiatorLifetime *g.GssLifetime, acceptorLifetime *g.GssLifetime, mutate bool, opts ...g.CredStoreOption) (g.Credential, error) {
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

	credStore := newCredStore()
	for _, opt := range opts {
		if err := opt(&credStore); err != nil {
			return nil, err
		}
	}

	kv := credStore.kv()
	defer kv.Release()

	var minor C.OM_uint32
	var cCredOut C.gss_cred_id_t = C.GSS_C_NO_CREDENTIAL
	var cpCredOut *C.gss_cred_id_t = nil
	if !mutate {
		cpCredOut = &cCredOut
	}

	major := C._gss_add_cred_from(&minor, c.id, cGssName, cMechOid, C.int(usage), gssLifetimeToSeconds(initiatorLifetime), gssLifetimeToSeconds(acceptorLifetime), kv.kvset, cpCredOut, nil, nil, nil)
	if major != C.GSS_S_COMPLETE {
		return nil, makeMechStatus(major, minor, mech)
	}

	if mutate {
		return c, nil
	} else {
		return &Credential{id: cCredOut}, nil
	}
}
