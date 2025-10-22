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

	// this needs to be freed if not nil
	delegCred *Credential

	initOptions   *g.InitSecContextOptions
	acceptOptions *g.AcceptSecContextOptions
}

func newSecContext(isInitiator bool) SecContext {
	return SecContext{
		id:             C.GSS_C_NO_CONTEXT,
		continueNeeded: true,
		isInitiator:    isInitiator,
		initOptions:    &g.InitSecContextOptions{},
		acceptOptions:  &g.AcceptSecContextOptions{},
	}
}

// InitSecContext() is just a constructor for the context -- it does not perform any GSSAPI context establishment calls
func (provider) InitSecContext(name g.GssName, opts ...g.InitSecContextOption) (g.SecContext, error) {
	// The target name is required
	if name == nil {
		return nil, fmt.Errorf("InitSecContext: target name is required, %w", g.ErrBadName)
	}

	o := g.InitSecContextOptions{}
	for _, opt := range opts {
		opt(&o)
	}

	var nameImpl *GssName // impl not interface
	var ok bool
	nameImpl, ok = name.(*GssName) // name must be *our* impl
	if !ok {
		return nil, fmt.Errorf("bad name type %T, %w", name, g.ErrBadName)
	}

	savedName, err := nameImpl.Duplicate()
	if err != nil {
		return nil, fmt.Errorf("%w duplicating name: %w", g.ErrFailure, err)
	}

	ctx := newSecContext(true)
	ctx.initiatorName = savedName.(*GssName)
	ctx.mech = o.Mech
	ctx.initOptions = &o

	return &ctx, nil
}

func (provider) AcceptSecContext(opts ...g.AcceptSecContextOption) (g.SecContext, error) {
	o := g.AcceptSecContextOptions{}
	for _, opt := range opts {
		opt(&o)
	}

	ctx := newSecContext(false)
	ctx.acceptOptions = &o

	return &ctx, nil
}

// initSecContext() performs the GSSAPI context initialization using paramers supplied to InitSecContext()
func (c *SecContext) initSecContext() ([]byte, g.SecContextInfoPartial, error) {
	mech := g.Oid{} // the empty OID is mapped to GSS_C_NO_OID by oid2Coid

	// use a specific mech if requested in call to InitSecContext
	if c.initOptions.Mech != nil {
		mech = c.initOptions.Mech.Oid()
	}
	cMechOid, pinner := oid2Coid(mech, nil)
	defer pinner.Unpin()

	// get the C cred ID and name
	var cGssCred C.gss_cred_id_t = C.GSS_C_NO_CREDENTIAL
	if c.initOptions.Credential != nil {
		credImpl, ok := c.initOptions.Credential.(*Credential) // must be *our* impl
		if !ok {
			return nil, g.SecContextInfoPartial{}, fmt.Errorf("bad credential type %T, %w", credImpl, g.ErrDefectiveCredential)
		}

		cGssCred = credImpl.id
	}

	var cGssTargetName C.gss_name_t = c.initiatorName.name

	var cChBindings C.gss_channel_bindings_t = C.GSS_C_NO_CHANNEL_BINDINGS
	if c.initOptions.ChannelBinding != nil {
		cChBindings, pinner = mkChannelBindings(c.initOptions.ChannelBinding, pinner)
	}

	var minor C.OM_uint32
	var cGssCtxID C.gss_ctx_id_t = C.GSS_C_NO_CONTEXT
	var cOutToken C.gss_buffer_desc = C.gss_empty_buffer // cOutToken.value allocated by GSSAPI; released by *1
	major := C.gss_init_sec_context(&minor, cGssCred, &cGssCtxID, cGssTargetName, cMechOid, C.OM_uint32(c.initOptions.Flags), C.OM_uint32(c.initOptions.Lifetime.Seconds()), cChBindings, nil, nil, &cOutToken, nil, nil)

	if major != C.GSS_S_COMPLETE && (major&C.GSS_S_CONTINUE_NEEDED) == 0 {
		return nil, g.SecContextInfoPartial{}, makeMechStatus(major, minor, c.initOptions.Mech)
	}

	// *1  release GSSAPI allocated buffer
	defer C.gss_release_buffer(&minor, &cOutToken)

	var outToken []byte = nil
	if cOutToken != C.gss_empty_buffer {
		outToken = C.GoBytes(cOutToken.value, C.int(cOutToken.length))
	}
	c.continueNeeded = (major & C.GSS_S_CONTINUE_NEEDED) > 0
	c.id = cGssCtxID
	info := g.SecContextInfoPartial{}

	return outToken, info, nil
}

func (c *SecContext) acceptSecContext(inputToken []byte) ([]byte, g.SecContextInfoPartial, error) {
	// get the C cred ID and name
	var cGssAcceptorCred, cGssDelegCred C.gss_cred_id_t = C.GSS_C_NO_CREDENTIAL, C.GSS_C_NO_CREDENTIAL
	if c.acceptOptions.Credential != nil {
		credImpl, ok := c.acceptOptions.Credential.(*Credential) // must be *our* impl
		if !ok {
			return nil, g.SecContextInfoPartial{}, fmt.Errorf("bad credential type %T, %w", credImpl, g.ErrDefectiveCredential)
		}

		cGssAcceptorCred = credImpl.id
	}

	pinner := &runtime.Pinner{}
	defer pinner.Unpin()

	var cChBindings C.gss_channel_bindings_t = C.GSS_C_NO_CHANNEL_BINDINGS
	if c.acceptOptions.ChannelBinding != nil {
		cChBindings, pinner = mkChannelBindings(c.acceptOptions.ChannelBinding, pinner)
	}

	var minor C.OM_uint32
	var cSrcAcceptorName C.gss_name_t = C.GSS_C_NO_NAME
	var cGssCtxID C.gss_ctx_id_t = C.GSS_C_NO_CONTEXT
	var cOutToken C.gss_buffer_desc = C.gss_empty_buffer // cOutToken.value allocated by GSSAPI; released by *1
	cInputToken, pinner := bytesToCBuffer(inputToken, pinner)

	major := C.gss_accept_sec_context(&minor, &cGssCtxID, cGssAcceptorCred, &cInputToken, cChBindings, &cSrcAcceptorName, nil, &cOutToken, nil, nil, &cGssDelegCred)
	if major != C.GSS_S_COMPLETE && major != C.GSS_S_CONTINUE_NEEDED {
		return nil, g.SecContextInfoPartial{}, makeStatus(major, minor)
	}

	// *1  release GSSAPI allocated buffer
	defer C.gss_release_buffer(&minor, &cOutToken)

	if cGssDelegCred != C.GSS_C_NO_CREDENTIAL {
		c.delegCred = &Credential{cGssDelegCred, g.CredUsageInitiateOnly, false}
	}

	var outToken []byte = nil
	if cOutToken != C.gss_empty_buffer {
		outToken = C.GoBytes(cOutToken.value, C.int(cOutToken.length))
	}
	c.continueNeeded = (major & C.GSS_S_CONTINUE_NEEDED) != 0
	c.id = cGssCtxID
	c.acceptorName = nameFromGssInternal(cSrcAcceptorName)
	info := g.SecContextInfoPartial{}
	return outToken, info, nil
}

func (provider) ImportSecContext(token []byte) (g.SecContext, error) {
	var minor C.OM_uint32
	var cGssCtxID C.gss_ctx_id_t = C.GSS_C_NO_CONTEXT

	cToken, pinner := bytesToCBuffer(token, nil)
	defer pinner.Unpin()

	major := C.gss_import_sec_context(&minor, &cToken, &cGssCtxID)
	if major != C.GSS_S_COMPLETE {
		return nil, makeStatus(major, minor)
	}

	return &SecContext{
		id: cGssCtxID,
	}, nil

}

func (c *SecContext) Continue(inputToken []byte) ([]byte, g.SecContextInfoPartial, error) {
	// if the context is not yet initialized then do that..
	if c.id == nil {
		if c.isInitiator {
			return c.initSecContext()
		} else {
			return c.acceptSecContext(inputToken)
		}
	}

	info := g.SecContextInfoPartial{}

	// otherwise continue establishing the context..
	//
	var major, minor C.OM_uint32
	var cOutToken C.gss_buffer_desc = C.gss_empty_buffer // cOutToken.value allocated by GSSAPI; released by *1
	cInputToken, pinner := bytesToCBuffer(inputToken, nil)
	defer pinner.Unpin()

	mech := g.Oid{} // empty oid mapped to GSS_C_NO_OID by oid2Coid
	if c.mech != nil {
		mech = c.mech.Oid()
	}
	cMechOid, pinner := oid2Coid(mech, pinner)

	if c.isInitiator {
		major = C.gss_init_sec_context(&minor, C.GSS_C_NO_CREDENTIAL, &c.id, c.initiatorName.name, cMechOid, 0, 0, nil, &cInputToken, nil, &cOutToken, nil, nil)
	} else {
		major = C.gss_accept_sec_context(&minor, &c.id, C.GSS_C_NO_CREDENTIAL, &cInputToken, nil, nil, nil, &cOutToken, nil, nil, nil)
	}

	if major != C.GSS_S_COMPLETE && major != C.GSS_S_CONTINUE_NEEDED {
		return nil, info, makeStatus(major, minor)
	}

	// *1  release GSSAPI allocated buffer
	defer C.gss_release_buffer(&minor, &cOutToken)

	var outToken []byte = nil
	if cOutToken != C.gss_empty_buffer {
		outToken = C.GoBytes(cOutToken.value, C.int(cOutToken.length))
	}

	c.continueNeeded = major == C.GSS_S_CONTINUE_NEEDED
	return outToken, info, nil
}

func (c *SecContext) ContinueNeeded() bool {
	return c.continueNeeded
}

func (c *SecContext) Delete() ([]byte, error) {
	if c == nil {
		return nil, nil
	}
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

	if c.delegCred != nil {
		if err := c.delegCred.Release(); err != nil {
			return nil, err
		}
		c.delegCred = nil
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

// ProcessToken is used to process error tokens from the peero.  No idea how to test this!
func (c *SecContext) ProcessToken(token []byte) error {
	var minor C.OM_uint32
	cInputToken, pinner := bytesToCBuffer(token, nil)
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

	c.initiatorName = nameFromGssInternal(cSrcName)
	c.acceptorName = nameFromGssInternal(cTargName)

	oid := oidFromGssOid(cMechOid)
	mech, err := g.MechFromOid(oid)
	if err != nil {
		if cMechOid == C.GSS_C_NO_OID && isHeimdalMac() {
			mech = g.GSS_MECH_KRB5
		} else {
			return nil, err
		}
	}

	// treat protection and transferrable flags separately -- they are not
	// request flags and are unknown to the interface
	protFlag := cFlags & C.GSS_C_PROT_READY_FLAG
	transFlag := cFlags & C.GSS_C_TRANS_FLAG

	cFlags &= ^C.OM_uint32(C.GSS_C_PROT_READY_FLAG | C.GSS_C_TRANS_FLAG)

	return &g.SecContextInfo{
		SecContextInfoPartial: g.SecContextInfoPartial{
			InitiatorName:    c.initiatorName,
			Mech:             mech,
			Flags:            g.ContextFlag(cFlags),
			ExpiresAt:        timeRecToGssLifetime(cLifetime),
			LocallyInitiated: cLocallyInitiated != 0,
			FullyEstablished: cOpen != 0,
			ProtectionReady:  protFlag > 0,
			Transferrable:    transFlag > 0,
		},
		AcceptorName: c.acceptorName,
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

	cInputMessage, pinner := bytesToCBuffer(msgIn, nil)
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

	cInputMessage, pinner := bytesToCBuffer(msgIn, nil)
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

	cMessage, pinner := bytesToCBuffer(msg, nil)
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

	cMessage, pinner := bytesToCBuffer(msg, nil)
	defer pinner.Unpin()
	cToken, pinner := bytesToCBuffer(token, pinner)

	var minor C.OM_uint32
	var cQoP C.gss_qop_t
	major := C.gss_verify_mic(&minor, c.id, &cMessage, &cToken, &cQoP)
	return g.QoP(cQoP), makeStatus(major, minor)
}
