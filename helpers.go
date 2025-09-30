// SPDX-License-Identifier: Apache-2.0

package gssapi

/*
#include "gss.h"
*/
import "C"

import (
	"net"
	"runtime"
	"unsafe"

	g "github.com/golang-auth/go-gssapi/v3"
)

// Convert from a C OID set to slice of OID objects
func oidsFromGssOidSet(oidSet C.gss_OID_set) []g.Oid {
	ret := make([]g.Oid, oidSet.count)

	var oidArray *C.gss_OID_desc = oidSet.elements
	oidSlice := unsafe.Slice(oidArray, oidSet.count)
	for i, cOid := range oidSlice {
		ret[i] = oidFromGssOid(&cOid)
	}

	return ret
}

// Convert from a slice of OID object to a set of C OIDS (see below)
func gssOidSetFromOids(oids []g.Oid) gssOidSet {
	ret := gssOidSet{}

	if len(oids) > 0 {
		ret.oidPtrs = make([]C.gss_OID, len(oids))

		for i, oid := range oids {
			ret.oidPtrs[i] = oid2Coid(oid)
		}

		ret.oidSet = &C.gss_OID_set_desc{C.size_t(len(oids)), ret.oidPtrs[0]}
	}

	return ret
}

// Wrap a C GSS OID set such that we can pin and then unpin the underlying pointers
// so that the garbage collector doesn't touch them while they are being used
// by the C layer.
type gssOidSet struct {
	pinner  runtime.Pinner
	oidSet  C.gss_OID_set
	oidPtrs []C.gss_OID
}

// Pin the pointers in the OID set
func (oidset *gssOidSet) Pin() {
	for _, p := range oidset.oidPtrs {
		oidset.pinner.Pin(p)
	}
}

// Unpin the pointers
func (oidset *gssOidSet) Unpin() {
	oidset.pinner.Unpin()
}

// Convert Go GSSAPI interface mech names to a set of mech OIDs
func mechsToOids(mechs []g.GssMech) []g.Oid {
	ret := make([]g.Oid, len(mechs))
	for i, mech := range mechs {
		ret[i] = mech.Oid()
	}

	return ret
}

// Create a GSS buffer pointing to Go bytes, and pin the Go bytes
// so that the garbage collector doesn't touch the memory.  Return the
// pinner, which should be used to unpin the memory after the C function
// returns.
func bytesToCBuffer(b []byte) (C.gss_buffer_desc, runtime.Pinner) {
	pinner := runtime.Pinner{}

	value := unsafe.Pointer(nil)
	if len(b) > 0 {
		value = unsafe.Pointer(&b[0])
		pinner.Pin(&b[0])
	}
	ret := C.gss_buffer_desc{
		length: C.size_t(len(b)),
		value:  value,
	}

	return ret, pinner
}

func addrToGssBuff(addr net.Addr) (g.GssAddressFamily, C.gss_buffer_desc) {
	var addrType g.GssAddressFamily
	addrData := []byte{}

	switch a := addr.(type) {
	case *net.IPAddr:
		addrType = g.GssAddrFamilyINET
		addrData = ipData(a.IP)
	case *net.TCPAddr:
		addrType = g.GssAddrFamilyINET
		addrData = ipData(a.IP)
	case *net.UDPAddr:
		addrType = g.GssAddrFamilyINET
		addrData = ipData(a.IP)
	case *net.UnixAddr:
		addrType = g.GssAddrFamilyLOCAL
		addrData = []byte(a.Name)
	}

	var addrValue unsafe.Pointer
	if len(addrData) > 0 {
		addrValue = unsafe.Pointer(&addrData[0])
	}

	// the pointer (value) is pinned by the caller (mkChannelBindings)
	return addrType, C.gss_buffer_desc{
		length: C.size_t(len(addrData)),
		value:  addrValue,
	}
}

func ipData(addr net.IP) (ret net.IP) {
	if ret = addr.To4(); ret != nil {
		return ret
	}

	if ret = addr.To16(); ret != nil {
		return ret
	}

	return nil
}

func gssLifetimeToSeconds(lifetime *g.GssLifetime) C.OM_uint32 {
	if lifetime == nil {
		return C.GSS_C_INDEFINITE
	}

	switch lifetime.Status {
	case g.GssLifetimeIndefinite:
		return C.GSS_C_INDEFINITE
	case g.GssLifetimeExpired:
		return C.OM_uint32(0)
	default:
		return C.OM_uint32(lifetime.ExpiresAt.Unix())
	}
}

func extractBufferSet(bs C.gss_buffer_set_t) [][]byte {
	out := make([][]byte, bs.count)

	bufSlice := unsafe.Slice(bs.elements, bs.count)
	for i, buf := range bufSlice {
		out[i] = C.GoBytes(buf.value, C.int(buf.length))
	}

	return out
}
