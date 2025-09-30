// SPDX-License-Identifier: Apache-2.0

package gssapi

/*
#include "gss.h"

// The function pointers below are set to the actual function pointers in the library
// by the init function using symbolMap.Apply()

OM_uint32 (*__gogssapi_ccache_name)(OM_uint32 *, const char *, const char **)= NULL;
static OM_uint32 _gogssapi_ccache_name(OM_uint32 *minor, const char *ccache_name) {
	if( __gogssapi_ccache_name == NULL ) {
		*minor = 0;
		return GSS_S_UNAVAILABLE;
	}
	return __gogssapi_ccache_name(minor, ccache_name, NULL);
}


OM_uint32 (*__gogssapi_register_acceptor_identity)(const char *)= NULL;
static OM_uint32 _gogssapi_register_acceptor_identity(const char *identity) {
	if( __gogssapi_register_acceptor_identity == NULL ) {
		return GSS_S_UNAVAILABLE;
	}
	return __gogssapi_register_acceptor_identity(identity);
}

*/
import "C"

import (
	"unsafe"
)

// Map optional symbols from the GSSAPI library to the wrapper function pointers
var providerSymbols = symbolMap{
	"krb5_gss_register_acceptor_identity": &C.__gogssapi_register_acceptor_identity,
	"gsskrb5_register_acceptor_identity":  &C.__gogssapi_register_acceptor_identity,
	"gss_krb5_ccache_name":                &C.__gogssapi_ccache_name,
}

func init() {
	providerSymbols.Apply()
}

func (p *provider) RegisterAcceptorIdentity(identity string) error {
	cIdentity := C.CString(identity)
	defer C.free(unsafe.Pointer(cIdentity))

	major := C._gogssapi_register_acceptor_identity(cIdentity)
	if major != C.GSS_S_COMPLETE {
		return makeStatus(major, 0)
	}

	return nil
}

func (p *provider) SetCCacheName(ccacheName string) error {
	cName := C.CString(ccacheName)
	defer C.free(unsafe.Pointer(cName))

	cMinor := C.OM_uint32(0)
	cMajor := C._gogssapi_ccache_name(&cMinor, cName)
	if cMajor != C.GSS_S_COMPLETE {
		return makeStatus(cMajor, cMinor)
	}
	return nil
}
