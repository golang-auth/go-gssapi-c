// SPDX-License-Identifier: Apache-2.0

package gssapi

/*
#include "gss.h"
*/
import "C"

import (
	"fmt"
	"math"
	"runtime"
	"time"

	g "github.com/golang-auth/go-gssapi/v3"
)

type SecContext struct {
	id             C.gss_ctx_id_t
	continueNeeded bool
	isInitiator    bool
	mech           g.GssMech

	// both of these need to be freed if not nil
	initiatorName *GssName
	acceptorName  *GssName

	initOptions *g.InitSecContextOptions
}

func hasChannelBound() bool {
	return C.has_channel_bound() == 1
}

// InitSecContext() is just a constructor for the context -- it does not perform any GSSAPI calls
func (provider) InitSecContext(name g.GssName, opts ...g.InitSecContextOption) (g.SecContext, error) {
	o := g.InitSecContextOptions{}
	for _, opt := range opts {
		opt(&o)
	}

	var nameImpl *GssName // impl not interface
	if name != nil {
		var ok bool
		nameImpl, ok = name.(*GssName) // name must be *our* impl
		if !ok {
			return nil, fmt.Errorf("bad name type %T, %w", name, g.ErrBadName)
		}
	}

	savedName, err := nameImpl.Duplicate()
	if err != nil {
		return nil, fmt.Errorf("%w duplicating name: %w", g.ErrFailure, err)
	}

	return &SecContext{
		isInitiator:    true,
		continueNeeded: true,
		initiatorName:  savedName.(*GssName),
		mech:           o.Mech,
		initOptions:    &o,
	}, nil
}

func (provider) AcceptSecContext(cred g.Credential, cb *g.ChannelBinding) (g.SecContext, error) {
	return &SecContext{
		isInitiator: false,
		initOptions: &g.InitSecContextOptions{
			Credential:     cred,
			ChannelBinding: cb,
		},
	}, nil
}

// initSecContext() performs the GSSAPI context initialization using paramers supplied to InitSecContext()
func (c *SecContext) initSecContext() ([]byte, error) {
	mech := g.Oid{} // the empty OID is mapped to GSS_C_NO_OID by oid2Coid

	// use a specific mech if requested in call to InitSecContext
	if c.initOptions.Mech != nil {
		mech = c.initOptions.Mech.Oid()
	}
	cMechOid := oid2Coid(mech)

	// get the C cred ID and name
	var cGssCred C.gss_cred_id_t = C.GSS_C_NO_CREDENTIAL
	if c.initOptions.Credential != nil {
		credImpl, ok := c.initOptions.Credential.(*Credential) // must be *our* impl
		if !ok {
			return nil, fmt.Errorf("bad credential type %T, %w", credImpl, g.ErrDefectiveCredential)
		}

		cGssCred = credImpl.id
	}

	var cGssName C.gss_name_t = c.initiatorName.name

	var cChBindings C.gss_channel_bindings_t = C.GSS_C_NO_CHANNEL_BINDINGS
	pinnerCB := runtime.Pinner{}
	if c.initOptions.ChannelBinding != nil {
		cChBindings, pinnerCB = mkChannelBindings(c.initOptions.ChannelBinding)
	}
	defer pinnerCB.Unpin()

	var minor C.OM_uint32
	var cGssCtxId C.gss_ctx_id_t = C.GSS_C_NO_CONTEXT
	var cOutToken C.gss_buffer_desc = C.gss_empty_buffer // cOutToken.value allocated by GSSAPI; released by *1
	major := C.gss_init_sec_context(&minor, cGssCred, &cGssCtxId, cGssName, cMechOid, C.OM_uint32(c.initOptions.Flags), C.OM_uint32(c.initOptions.Lifetime.Seconds()), cChBindings, nil, nil, &cOutToken, nil, nil)

	if major != C.GSS_S_COMPLETE && major != C.GSS_S_CONTINUE_NEEDED {
		return nil, makeMechStatus(major, minor, c.initOptions.Mech)
	}

	// *1  release GSSAPI allocated buffer
	defer C.gss_release_buffer(&minor, &cOutToken)

	pinnerCB.Unpin()

	outToken := C.GoBytes(cOutToken.value, C.int(cOutToken.length))
	c.continueNeeded = major == C.GSS_S_CONTINUE_NEEDED
	c.id = cGssCtxId

	return outToken, nil
}

func (c *SecContext) acceptSecContext(inputToken []byte) ([]byte, error) {
	// get the C cred ID and name
	var cGssCred C.gss_cred_id_t = C.GSS_C_NO_CREDENTIAL
	if c.initOptions.Credential != nil {
		credImpl, ok := c.initOptions.Credential.(*Credential) // must be *our* impl
		if !ok {
			return nil, fmt.Errorf("bad credential type %T, %w", credImpl, g.ErrDefectiveCredential)
		}

		cGssCred = credImpl.id
	}

	var cChBindings C.gss_channel_bindings_t = C.GSS_C_NO_CHANNEL_BINDINGS
	pinnerCb := runtime.Pinner{}
	if c.initOptions.ChannelBinding != nil {
		cChBindings, pinnerCb = mkChannelBindings(c.initOptions.ChannelBinding)
	}
	defer pinnerCb.Unpin()

	var minor C.OM_uint32
	var cSrcName C.gss_name_t = C.GSS_C_NO_NAME
	var cGssCtxId C.gss_ctx_id_t = C.GSS_C_NO_CONTEXT
	var cOutToken C.gss_buffer_desc = C.gss_empty_buffer // cOutToken.value allocated by GSSAPI; released by *1
	cInputToken, pinner := bytesToCBuffer(inputToken)
	defer pinner.Unpin()

	major := C.gss_accept_sec_context(&minor, &cGssCtxId, cGssCred, &cInputToken, cChBindings, &cSrcName, nil, &cOutToken, nil, nil, nil)
	if major != C.GSS_S_COMPLETE && major != C.GSS_S_CONTINUE_NEEDED {
		return nil, makeStatus(major, minor)
	}

	// *1  release GSSAPI allocated buffer
	defer C.gss_release_buffer(&minor, &cOutToken)

	pinnerCb.Unpin()

	outToken := C.GoBytes(cOutToken.value, C.int(cOutToken.length))
	c.id = cGssCtxId
	c.acceptorName = &GssName{cSrcName}
	return outToken, nil
}

func (provider) ImportSecContext(token []byte) (g.SecContext, error) {
	var minor C.OM_uint32
	var cGssCtxId C.gss_ctx_id_t = C.GSS_C_NO_CONTEXT

	cToken, pinner := bytesToCBuffer(token)
	defer pinner.Unpin()

	major := C.gss_import_sec_context(&minor, &cToken, &cGssCtxId)
	if major != C.GSS_S_COMPLETE {
		return nil, makeStatus(major, minor)
	}

	return &SecContext{
		id: cGssCtxId,
	}, nil

}

func (c *SecContext) Continue(inputToken []byte) ([]byte, error) {
	// if the context is not yet initialized then do that..
	if c.id == nil {
		if c.isInitiator {
			return c.initSecContext()
		} else {
			return c.acceptSecContext(inputToken)
		}
	}

	// otherwise continue establishing the context..
	//
	var major, minor C.OM_uint32
	var cOutToken C.gss_buffer_desc = C.gss_empty_buffer // cOutToken.value allocated by GSSAPI; released by *1
	cInputToken, pinner := bytesToCBuffer(inputToken)
	defer pinner.Unpin()

	mech := g.Oid{} // empty oid mapped to GSS_C_NO_OID by oid2Coid
	if c.mech != nil {
		mech = c.mech.Oid()
	}
	cMechOid := oid2Coid(mech)

	// TODO : RFC2743 requires that the claimant cred handle be re-used between calls
	if c.isInitiator {
		major = C.gss_init_sec_context(&minor, C.GSS_C_NO_CREDENTIAL, &c.id, c.initiatorName.name, cMechOid, 0, 0, nil, &cInputToken, nil, &cOutToken, nil, nil)
	} else {
		major = C.gss_accept_sec_context(&minor, &c.id, C.GSS_C_NO_CREDENTIAL, &cInputToken, nil, nil, nil, &cOutToken, nil, nil, nil)
	}

	if major != C.GSS_S_COMPLETE && major != C.GSS_S_CONTINUE_NEEDED {
		return nil, makeStatus(major, minor)
	}

	// *1  release GSSAPI allocated buffer
	defer C.gss_release_buffer(&minor, &cOutToken)

	outToken := C.GoBytes(cOutToken.value, C.int(cOutToken.length))
	c.continueNeeded = major == C.GSS_S_CONTINUE_NEEDED
	return outToken, nil
}

func (c *SecContext) ContinueNeeded() bool {
	return c.continueNeeded
}

func (c *SecContext) Delete() ([]byte, error) {
	if c.initiatorName != nil {
		if err := c.initiatorName.Release(); err != nil {
			return nil, err
		}
		c.initiatorName = nil
	}

	if c.acceptorName != nil {
		if err := c.acceptorName.Release(); err != nil {
			return nil, err
		}
		c.acceptorName = nil
	}

	if c.id == nil {
		return nil, nil
	}
	var minor C.OM_uint32
	var cOutToken C.gss_buffer_desc = C.gss_empty_buffer // allocated by GSSAPI;  released by *1
	major := C.gss_delete_sec_context(&minor, &c.id, &cOutToken)

	// *1   Release GSSAPI allocated buffer
	defer C.gss_release_buffer(&minor, &cOutToken)

	c.id = nil
	outToken := C.GoBytes(cOutToken.value, C.int(cOutToken.length))

	return outToken, makeStatus(major, minor)
}

// no idea how to test this!
func (c *SecContext) ProcessToken(token []byte) error {
	var minor C.OM_uint32
	cInputToken, pinner := bytesToCBuffer(token)
	defer pinner.Unpin()

	major := C.gss_process_context_token(&minor, c.id, &cInputToken)
	if major != C.GSS_S_COMPLETE {
		return makeStatus(major, minor)
	}

	return nil
}

func (c *SecContext) ExpiresAt() (*g.GssLifetime, error) {
	var minor C.OM_uint32
	var cTimeRec C.OM_uint32
	major := C.gss_context_time(&minor, c.id, &cTimeRec)
	if major != C.GSS_S_COMPLETE {
		return nil, makeStatus(major, minor)
	}

	lifetime := timeRecToGssLifetime(cTimeRec)
	return &lifetime, nil
}

func timeRecToGssLifetime(cTimeRec C.OM_uint32) g.GssLifetime {
	lifetime := g.GssLifetime{}

	switch cTimeRec {
	default:
		lifetime.ExpiresAt = time.Now().Add(time.Duration(cTimeRec) * time.Second)
	case C.GSS_C_INDEFINITE:
		lifetime.Status |= g.GssLifetimeIndefinite
	case 0:
		lifetime.Status |= g.GssLifetimeExpired
	}

	return lifetime
}

func (c *SecContext) Inquire() (*g.SecContextInfo, error) {
	if c.id == nil {
		return nil, g.ErrNoContext
	}

	var minor C.OM_uint32
	var cSrcName, cTargName C.gss_name_t = C.GSS_C_NO_NAME, C.GSS_C_NO_NAME // allocated by GSSAPI;  released by SecContext.Delete()
	var cLifetime, cFlags C.OM_uint32
	var cMechOid C.gss_OID = C.GSS_C_NO_OID // do not free, pointer to static value returned
	var cLocallyInitiated, cOpen C.int
	major := C.gss_inquire_context(&minor, c.id, &cSrcName, &cTargName, &cLifetime, &cMechOid, &cFlags, &cLocallyInitiated, &cOpen)

	if major != C.GSS_S_COMPLETE {
		return nil, makeStatus(major, minor)
	}

	// It is convenient to replace the initiator/acceptor names stored on the SecConext because those
	// are freed when the context is deleted.  That means we don't need to have the caller of Inquire()
	// free these directly.
	if c.initiatorName != nil {
		_ = c.initiatorName.Release()
	}
	if c.acceptorName != nil {
		_ = c.acceptorName.Release()
	}

	c.initiatorName = &GssName{cSrcName}
	c.acceptorName = &GssName{cTargName}

	mech, err := g.MechFromOid(oidFromGssOid(cMechOid))
	if err != nil {
		return nil, err
	}

	// treat protection and transferrable flags separately -- they are not
	// request flags and are unknown to the interface
	protFlag := cFlags & C.GSS_C_PROT_READY_FLAG
	transFlag := cFlags & C.GSS_C_TRANS_FLAG

	cFlags &= ^C.OM_uint32(C.GSS_C_PROT_READY_FLAG | C.GSS_C_TRANS_FLAG)

	return &g.SecContextInfo{
		InitiatorName:    c.initiatorName,
		AcceptorName:     c.acceptorName,
		Mech:             mech,
		Flags:            g.ContextFlag(cFlags),
		ExpiresAt:        timeRecToGssLifetime(cLifetime),
		LocallyInitiated: cLocallyInitiated != 0,
		FullyEstablished: cOpen != 0,
		ProtectionReady:  protFlag > 0,
		Transferrable:    transFlag > 0,
	}, nil
}

func (c *SecContext) WrapSizeLimit(confRequired bool, maxWrapSize uint, qop g.QoP) (uint, error) {
	var minor C.OM_uint32
	var cConfReq C.int
	var cMaxInputSize C.OM_uint32

	// prevent potential overflows; message size may be derived from external input
	if maxWrapSize > math.MaxUint32 {
		return 0, ErrTooLarge
	}
	if qop > math.MaxUint32 {
		return 0, g.ErrBadQop
	}

	if confRequired {
		cConfReq = 1
	}

	major := C.gss_wrap_size_limit(&minor, c.id, cConfReq, C.gss_qop_t(qop), C.OM_uint32(maxWrapSize), &cMaxInputSize)
	if major != C.GSS_S_COMPLETE {
		return 0, makeStatus(major, minor)
	}

	// conversion is safe -- uint is either 32 or 64 bits here but cMaxInputSize is always 32 bit
	return uint(cMaxInputSize), nil
}

func (c *SecContext) Export() ([]byte, error) {
	var minor C.OM_uint32
	var cToken C.gss_buffer_desc = C.gss_empty_buffer // allocated by GSSAPI;  released by *1
	major := C.gss_export_sec_context(&minor, &c.id, &cToken)
	if major != 0 {
		return nil, makeStatus(major, minor)
	}

	defer C.gss_release_buffer(&minor, &cToken) // *1  Release GSSAPI allocated buffer

	// At this point the original security context has been deallocated and is no
	// longer valid

	outToken := C.GoBytes(cToken.value, C.int(cToken.length))

	return outToken, nil
}

func (c *SecContext) Wrap(msgIn []byte, confReq bool, qop g.QoP) ([]byte, bool, error) {
	// the C bindings support a 32 bit max message size..
	if len(msgIn) > math.MaxUint32 {
		return nil, false, ErrTooLarge
	}
	if qop > math.MaxUint32 {
		return nil, false, g.ErrBadQop
	}

	cInputMessage, pinner := bytesToCBuffer(msgIn)
	defer pinner.Unpin()

	var minor C.OM_uint32
	var cConfReq, cConfState C.int
	var cOutputMessage C.gss_buffer_desc = C.gss_empty_buffer // allocated by GSSAPI;  released by *1
	if confReq {
		cConfReq = 1
	}

	major := C.gss_wrap(&minor, c.id, cConfReq, C.gss_qop_t(qop), &cInputMessage, &cConfState, &cOutputMessage)
	if major != C.GSS_S_COMPLETE {
		return nil, false, makeStatus(major, minor)
	}

	defer C.gss_release_buffer(&minor, &cOutputMessage) // *1  Release GSSAPI allocated buffer

	msgOut := C.GoBytes(cOutputMessage.value, C.int(cOutputMessage.length))
	return msgOut, cConfState != 0, nil
}

func (c *SecContext) Unwrap(msgIn []byte) ([]byte, bool, g.QoP, error) {
	// the C bindings support a 32 bit max message size..
	if len(msgIn) > math.MaxUint32 {
		return nil, false, 0, ErrTooLarge
	}

	cInputMessage, pinner := bytesToCBuffer(msgIn)
	defer pinner.Unpin()

	var minor C.OM_uint32
	var cConfState C.int
	var cOutputMessage C.gss_buffer_desc = C.gss_empty_buffer // allocated by GSSAPI;  released by *1
	var cQoP C.gss_qop_t

	major := C.gss_unwrap(&minor, c.id, &cInputMessage, &cOutputMessage, &cConfState, &cQoP)
	if major != 0 {
		return nil, false, 0, makeStatus(major, minor)
	}

	defer C.gss_release_buffer(&minor, &cOutputMessage) // *1  Release GSSAPI allocated buffer

	msgOut := C.GoBytes(cOutputMessage.value, C.int(cOutputMessage.length))
	return msgOut, cConfState != 0, g.QoP(cQoP), nil
}

func (c *SecContext) GetMIC(msg []byte, qop g.QoP) ([]byte, error) {
	// the C bindings support a 32 bit max message size..
	if len(msg) > math.MaxUint32 {
		return nil, ErrTooLarge
	}
	if qop > math.MaxUint32 {
		return nil, g.ErrBadQop
	}

	cMessage, pinner := bytesToCBuffer(msg)
	defer pinner.Unpin()

	var minor C.OM_uint32
	var cMsgToken C.gss_buffer_desc = C.gss_empty_buffer // allocated by GSSAPI;  released by *1
	major := C.gss_get_mic(&minor, c.id, C.gss_qop_t(qop), &cMessage, &cMsgToken)
	if major != 0 {
		return nil, makeStatus(major, minor)
	}

	defer C.gss_release_buffer(&minor, &cMsgToken) // *1  Release GSSAPI allocated buffer

	token := C.GoBytes(cMsgToken.value, C.int(cMsgToken.length))
	return token, nil
}

func (c *SecContext) VerifyMIC(msg, token []byte) (g.QoP, error) {
	// the C bindings support a 32 bit max message size..
	if len(msg) > math.MaxUint32 {
		return 0, ErrTooLarge
	}

	cMessage, pinnerMsg := bytesToCBuffer(msg)
	defer pinnerMsg.Unpin()
	cToken, pinnerToken := bytesToCBuffer(token)
	defer pinnerToken.Unpin()

	var minor C.OM_uint32
	var cQoP C.gss_qop_t
	major := C.gss_verify_mic(&minor, c.id, &cMessage, &cToken, &cQoP)
	return g.QoP(cQoP), makeStatus(major, minor)
}
