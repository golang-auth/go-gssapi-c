//go:build !darwin && unix

// SPDX-License-Identifier: Apache-2.0

package gssapi

/*
#include "gss.h"


typedef struct gss_channel_bindings_struct gss_channel_bindings;

*/
import "C"
import (
	"runtime"
	"unsafe"

	g "github.com/golang-auth/go-gssapi/v3"
)

func mkChannelBindings(cb *g.ChannelBinding, pinner *runtime.Pinner) (C.gss_channel_bindings_t, *runtime.Pinner) {
	if pinner == nil {
		pinner = &runtime.Pinner{}
	}
	cCB := C.gss_channel_bindings{}

	if cb.InitiatorAddr != nil {
		af, addrBuf := addrToGssBuff(cb.InitiatorAddr)
		cCB.initiator_addrtype = C.OM_uint32(af)
		cCB.initiator_address = addrBuf
		pinner.Pin(addrBuf.value)
	}

	if cb.AcceptorAddr != nil {
		af, addrBuf := addrToGssBuff(cb.AcceptorAddr)
		cCB.acceptor_addrtype = C.OM_uint32(af)
		cCB.acceptor_address = addrBuf
		pinner.Pin(addrBuf.value)
	}

	cCB.application_data.length = C.size_t(len(cb.Data))
	cCB.application_data.value = unsafe.Pointer(&cb.Data[0])
	pinner.Pin(&cb.Data[0])

	return &cCB, pinner
}
