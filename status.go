// SPDX-License-Identifier: Apache-2.0

package gssapi

import (
	"errors"
	"fmt"

	g "github.com/golang-auth/go-gssapi/v3"
)

/*
#include "gss.h"
*/
import "C"

// FatalCallingError extends the go-gssapi FatalStatus type with a C-binding specific
// calling error (RFC 2744 § 3.9.1).  It is retrurned in cases that the C library
// populates bits 24-31 of the major error code returned from its functions.  These
// are programming errors made by the caller of the GSSPAI routines.  Note that not
// all of the C implementations make use of these calling errors - MIT does; Heimdal does
// not and will happily segfault instead.
//
// The Error() method adds details about the calling error to its output.  Generally this
// is sufficinent; if the caller needs to inspect the calling error it can check using
// [errors.Is()] and the ErrInaccessibleRead, ErrInaccessibleWrite and ErrBadStructure
// values.
type FatalCallingError struct {
	g.FatalStatus
	CallingErrorCode CallingErrorCode
}

// Errors specific to the C bindings
type CallingErrorCode uint32

const (
	inaccessibleRead CallingErrorCode = iota + 1
	inaccessibleWrite
	badStructure
)

// ErrInaccessibleRead is returned when an input parameter is null or otherwise invalid
var ErrInaccessibleRead = errors.New("a required input parameter could not be read")

// ErrInaccessibleWrite is returned when an output parameter is null or otherwise invalid
var ErrInaccessibleWrite = errors.New("a required output parameter could not be written")

// ErrBadStructure is returned when the value of a parameter is invalid
var ErrBadStructure = errors.New("a parameter was malformed")

// Calling() returns the calling error associated with the combined error
func (s FatalCallingError) Calling() error {
	switch s.CallingErrorCode {
	default:
		return g.ErrBadStatus
	case inaccessibleRead:
		return ErrInaccessibleRead
	case inaccessibleWrite:
		return ErrInaccessibleWrite
	case badStructure:
		return ErrBadStructure
	}
}

// Unwrap implements errors.Unwrap(), returning the individual errors
// comprising the combined FatalCallingError
func (s FatalCallingError) Unwrap() []error {
	ret := []error{}

	if s.CallingErrorCode != 0 {
		ret = append(ret, s.Calling())
	}

	ret = append(ret, s.FatalStatus.Unwrap()...)

	return ret
}

// Error() implements error.Error().  It returns the error string that
// [gssapi.FatalStatus()] would return, prepended by any calling
// errors.
func (s FatalCallingError) Error() string {
	var ret string

	if s.CallingErrorCode != 0 {
		ret = "C bindings errors: " + s.Calling().Error()
	}

	fatalErrs := s.FatalStatus.Error()
	if fatalErrs != "" {
		ret += ".  GSSAPI errors: " + fatalErrs
	}

	return ret
}

func makeStatus(major, minor C.OM_uint32) error {
	return makeMechStatus(major, minor, nil)
}

func makeMechStatus(major, minor C.OM_uint32, mech g.GssMech) error {
	if major == 0 {
		return nil
	}

	// see RFC 2744 § 3.9.1
	calling_error := (major & 0xFF000000) >> 24 // bad call by us to gssapi
	routine_error := (major & 0x00FF0000) >> 16 // the "Fatal" errors
	supplementary := major & 0xffff

	// all errors are at least informational
	info := g.InfoStatus{
		InformationCode: g.InformationCode(supplementary),
	}

	// minor codes are specific to the mech; there are no standard codes
	// so we just deposit error objects with description strings from
	// the C API
	if minor != 0 {
		minorErrors := gssMinorErrors(minor, mech)
		if len(minorErrors) > 0 {
			info.MechErrors = minorErrors
		}
	}

	// its just an informational if there is no calling or routine error
	if routine_error == 0 && calling_error == 0 {
		return info
	}

	// its always fatal if thre is a calling or routine error
	fatal := g.FatalStatus{
		FatalErrorCode: g.FatalErrorCode(routine_error),
		InfoStatus:     info,
	}

	// and just a fatal error from the interface if there is no calling error
	if calling_error == 0 {
		return fatal
	}

	// if there is a C binding calling error then indicate that..
	return FatalCallingError{
		CallingErrorCode: CallingErrorCode(calling_error),
		FatalStatus:      fatal,
	}
}

// Ask GSSAPI for the error strings associated with the minor (mech specific)
// error code
func gssMinorErrors(mechStatus C.OM_uint32, mech g.GssMech) []error {
	mechOid := g.Oid{}
	if mech != nil {
		mechOid = mech.Oid()
	}

	cMechOid := oid2Coid(mechOid)
	var minor, msgCtx C.OM_uint32
	var statusString C.gss_buffer_desc = C.gss_empty_buffer // Released in *1

	ret := []error{}

	for {
		major := C.gss_display_status(&minor, mechStatus, 2, cMechOid, &msgCtx, &statusString)
		if major != 0 {
			// specifically do not call makeStatus here - we might end up in a loop..
			ret = append(ret, fmt.Errorf("got GSS error %d/%d while finding string for minor code %d", major, minor, mechStatus))
			break
		}

		// *1 Release buffer
		defer C.gss_release_buffer(&minor, &statusString)

		s := C.GoStringN((*C.char)(statusString.value), C.int(statusString.length))
		ret = append(ret, errors.New(s))

		// all done when the message context is set to zero by gss_display_status
		if msgCtx == 0 {
			break
		}
	}

	return ret
}
