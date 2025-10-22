//go:build darwin

// SPDX-License-Identifier: Apache-2.0

package gssapi

/*
#include "gss.h"

typedef struct gss_channel_bindings_struct gss_channel_bindings;

// work around Go not understanding packed structs
void _set_cb_initiator(gss_channel_bindings_t cb,
					OM_uint32 addrtype,
					gss_buffer_desc address )
{
		cb->initiator_addrtype = addrtype;
		cb->initiator_address = address;
}
void _set_cb_acceptor(gss_channel_bindings_t cb,
					OM_uint32 addrtype,
					gss_buffer_desc address )
{
		cb->acceptor_addrtype = addrtype;
		cb->acceptor_address = address;
}
void _set_cb_data(gss_channel_bindings_t cb,
					gss_buffer_desc data )
{
		cb->application_data = data;
}
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
		C._set_cb_initiator(&cCB, C.OM_uint32(af), addrBuf)
		pinner.Pin(addrBuf.value)
	}

	if cb.AcceptorAddr != nil {
		af, addrBuf := addrToGssBuff(cb.AcceptorAddr)
		C._set_cb_acceptor(&cCB, C.OM_uint32(af), addrBuf)
		pinner.Pin(addrBuf.value)
	}

	buf := C.gss_buffer_desc{
		length: C.size_t(len(cb.Data)),
		value:  unsafe.Pointer(&cb.Data[0]),
	}

	C._set_cb_data(&cCB, buf)
	pinner.Pin(&cb.Data[0])

	return &cCB, pinner
}
