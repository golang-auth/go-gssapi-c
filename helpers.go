// SPDX-License-Identifier: Apache-2.0

package gssapi

/*
#include "gss.h"
*/
import "C"

import (
	"encoding/asn1"
	"fmt"
	"net"
	"runtime"
	"strings"
	"unsafe"

	g "github.com/golang-auth/go-gssapi/v3"
)

// Convert a Go OID to a string
func oid2String(oid g.Oid) (string, error) {
	objId := make(asn1.ObjectIdentifier, 100)

	oid = append([]byte{0x06, byte(len(oid))}, oid...)
	_, err := asn1.Unmarshal(oid, &objId)
	if err != nil {
		return "", err
	}

	var s strings.Builder
	for i, o := range objId {
		if i > 0 {
			s.WriteString(".")
		}
		s.WriteString(fmt.Sprintf("%d", o))
	}

	return s.String(), nil
}

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
func gssOidSetFromOids(oids []g.Oid, pinner *runtime.Pinner) (C.gss_OID_set, *runtime.Pinner) {
	if pinner == nil {
		pinner = &runtime.Pinner{}
	}

	if len(oids) == 0 {
		return nil, pinner
	}

	// Create a Go slice containing the C gss_OID elements, which is gauranteed to be
	// contiguous, and suitable for use as a C array
	oidPtrs := make([]C.gss_OID, len(oids))

	// All the OID pointers will be pinned after this loop
	for i, oid := range oids {
		// oid2Coid will pin memory pointed to by gss_OID.elements
		oidPtrs[i], pinner = oid2Coid(oid, pinner)

		// but we also need to pin the gss_OID struct itself because its a member
		// of gss_OID_set
		pinner.Pin(oidPtrs[i])
	}

	cOidSet := C.gss_OID_set_desc{
		count:    C.size_t(len(oids)),
		elements: oidPtrs[0],
	}

	return &cOidSet, pinner
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
func bytesToCBuffer(b []byte, pinner *runtime.Pinner) (C.gss_buffer_desc, *runtime.Pinner) {
	if pinner == nil {
		pinner = &runtime.Pinner{}
	}

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
