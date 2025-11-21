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

	// stash the initiator name so we can use it during the context establishment process
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
		cChBindings, _ = mkChannelBindings(c.initOptions.ChannelBinding, pinner)
	}

	var cMinor, cRetFlags, cTimeRec C.OM_uint32
	var cGssCtxID C.gss_ctx_id_t = C.GSS_C_NO_CONTEXT
	var cOutToken C.gss_buffer_desc = C.gss_empty_buffer // cOutToken.value allocated by GSSAPI; released by *1
	var cActualMech C.gss_OID = C.GSS_C_NO_OID           // DO NOT FREE
	cMajor := C.gss_init_sec_context(&cMinor, cGssCred, &cGssCtxID, cGssTargetName, cMechOid, C.OM_uint32(c.initOptions.Flags), C.OM_uint32(c.initOptions.Lifetime.Seconds()), cChBindings, nil, &cActualMech, &cOutToken, &cRetFlags, &cTimeRec)

	if cMajor != C.GSS_S_COMPLETE && (cMajor&C.GSS_S_CONTINUE_NEEDED) == 0 {
		return nil, g.SecContextInfoPartial{}, makeMechStatus(cMajor, cMinor, c.initOptions.Mech)
	}

	// *1  release GSSAPI allocated buffer
	defer C.gss_release_buffer(&cMinor, &cOutToken)

	var outToken []byte = nil
	if cOutToken != C.gss_empty_buffer {
		outToken = C.GoBytes(cOutToken.value, C.int(cOutToken.length))
	}
	c.continueNeeded = (cMajor & C.GSS_S_CONTINUE_NEEDED) > 0
	c.id = cGssCtxID

	ctxFlags, protFlag, transFlag := splitFlags(cRetFlags)

	info := g.SecContextInfoPartial{
		InitiatorName:       c.initiatorName,
		Flags:               ctxFlags,
		ExpiresAt:           timeRecToGssLifetime(cTimeRec),
		LocallyInitiated:    c.isInitiator,
		FullyEstablished:    !c.continueNeeded,
		ProtectionReady:     protFlag,
		Transferrable:       transFlag,
		DelegatedCredential: nil,
	}
	if cActualMech != C.GSS_C_NO_OID {
		mech, err := g.MechFromOid(oidFromGssOid(cActualMech))
		if err != nil {
			return outToken, info, fmt.Errorf("unknown mech returned from gss_init_sec_context: %w", g.ErrBadMech)
		}
		info.Mech = mech
	}

	return outToken, info, nil
}

// Prot and trans aren't really context flags - they are communicated with callers separately
func splitFlags(flags C.OM_uint32) (g.ContextFlag, bool, bool) {
	protFlag := flags & C.GSS_C_PROT_READY_FLAG
	transFlag := flags & C.GSS_C_TRANS_FLAG
	flags &= ^C.OM_uint32(C.GSS_C_PROT_READY_FLAG | C.GSS_C_TRANS_FLAG)
	return g.ContextFlag(flags), protFlag > 0, transFlag > 0
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

	var cMinor, cRetFlags, cTimeRec C.OM_uint32
	var cInitiatorName C.gss_name_t = C.GSS_C_NO_NAME
	var cGssCtxID C.gss_ctx_id_t = C.GSS_C_NO_CONTEXT
	var cOutToken C.gss_buffer_desc = C.gss_empty_buffer // cOutToken.value allocated by GSSAPI; released by *1
	var cActualMech C.gss_OID = C.GSS_C_NO_OID
	cInputToken, _ := bytesToCBuffer(inputToken, pinner)

	cMajor := C.gss_accept_sec_context(&cMinor, &cGssCtxID, cGssAcceptorCred, &cInputToken, cChBindings, &cInitiatorName, &cActualMech, &cOutToken, &cRetFlags, &cTimeRec, &cGssDelegCred)
	if cMajor != C.GSS_S_COMPLETE && (cMajor&C.GSS_S_CONTINUE_NEEDED) == 0 {
		return nil, g.SecContextInfoPartial{}, makeStatus(cMajor, cMinor)
	}

	// *1  release GSSAPI allocated buffer
	defer C.gss_release_buffer(&cMinor, &cOutToken)

	if cGssDelegCred != C.GSS_C_NO_CREDENTIAL {
		c.delegCred = &Credential{cGssDelegCred, g.CredUsageInitiateOnly, false}
	}

	var outToken []byte = nil
	if cOutToken != C.gss_empty_buffer {
		outToken = C.GoBytes(cOutToken.value, C.int(cOutToken.length))
	}
	c.continueNeeded = (cMajor & C.GSS_S_CONTINUE_NEEDED) > 0
	c.id = cGssCtxID
	c.initiatorName = nameFromGssInternal(cInitiatorName)

	ctxFlags, protFlag, transFlag := splitFlags(cRetFlags)

	info := g.SecContextInfoPartial{
		InitiatorName:       c.initiatorName,
		Flags:               ctxFlags,
		ExpiresAt:           timeRecToGssLifetime(cTimeRec),
		LocallyInitiated:    c.isInitiator,
		FullyEstablished:    !c.continueNeeded,
		ProtectionReady:     protFlag,
		Transferrable:       transFlag,
		DelegatedCredential: c.delegCred,
	}
	if cActualMech != C.GSS_C_NO_OID {
		mech, err := g.MechFromOid(oidFromGssOid(cActualMech))
		if err != nil {
			return nil, g.SecContextInfoPartial{}, fmt.Errorf("unknown mech returned from gss_accept_sec_context: %w", g.ErrBadMech)
		}
		info.Mech = mech
	}

	return outToken, info, nil
}

func (provider) ImportSecContext(token []byte) (g.SecContext, error) {
	var cMinor C.OM_uint32
	var cGssCtxID C.gss_ctx_id_t = C.GSS_C_NO_CONTEXT

	cToken, pinner := bytesToCBuffer(token, nil)
	defer pinner.Unpin()

	cMajor := C.gss_import_sec_context(&cMinor, &cToken, &cGssCtxID)
	if cMajor != C.GSS_S_COMPLETE {
		return nil, makeStatus(cMajor, cMinor)
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

	// otherwise continue establishing the context..
	//
	var cMajor, cMinor, cRetFlags, cTimeRec C.OM_uint32
	var cOutToken C.gss_buffer_desc = C.gss_empty_buffer // cOutToken.value allocated by GSSAPI; released by *1
	var cActualMech C.gss_OID = C.GSS_C_NO_OID
	var cInitiatorName C.gss_name_t = C.GSS_C_NO_NAME
	var cGssDelegCred C.gss_cred_id_t = C.GSS_C_NO_CREDENTIAL
	cInputToken, pinner := bytesToCBuffer(inputToken, nil)
	defer pinner.Unpin()

	mech := g.Oid{} // empty oid mapped to GSS_C_NO_OID by oid2Coid
	if c.mech != nil {
		mech = c.mech.Oid()
	}
	cMechOid, _ := oid2Coid(mech, pinner)

	if c.isInitiator {
		cMajor = C.gss_init_sec_context(&cMinor, C.GSS_C_NO_CREDENTIAL, &c.id, c.initiatorName.name, cMechOid, 0, 0, nil, &cInputToken, &cActualMech, &cOutToken, &cRetFlags, &cTimeRec)
	} else {
		// Ask for the initiator name and delegated credential if we don't already have them
		var cpInitiatorName *C.gss_name_t = nil
		if c.initiatorName != nil {
			cpInitiatorName = &cInitiatorName
		}
		var cpGssDelegCred *C.gss_cred_id_t = nil
		if c.delegCred != nil {
			cpGssDelegCred = &cGssDelegCred
		}
		cMajor = C.gss_accept_sec_context(&cMinor, &c.id, C.GSS_C_NO_CREDENTIAL, &cInputToken, nil, cpInitiatorName, &cActualMech, &cOutToken, &cRetFlags, &cTimeRec, cpGssDelegCred)
	}

	if cMajor != C.GSS_S_COMPLETE && cMajor != C.GSS_S_CONTINUE_NEEDED {
		return nil, g.SecContextInfoPartial{}, makeStatus(cMajor, cMinor)
	}

	// *1  release GSSAPI allocated buffer
	defer C.gss_release_buffer(&cMinor, &cOutToken)

	// only if we're an acceptor and didn't already have a delegated credential
	if cGssDelegCred != C.GSS_C_NO_CREDENTIAL {
		c.delegCred = &Credential{cGssDelegCred, g.CredUsageInitiateOnly, false}
	}
	// only if we're an acceptor and didn't already have an initiator name
	if cInitiatorName != C.GSS_C_NO_NAME {
		c.initiatorName = nameFromGssInternal(cInitiatorName)
	}

	var outToken []byte = nil
	if cOutToken != C.gss_empty_buffer {
		outToken = C.GoBytes(cOutToken.value, C.int(cOutToken.length))
	}
	c.continueNeeded = cMajor&C.GSS_S_CONTINUE_NEEDED > 0

	ctxFlags, protFlag, transFlag := splitFlags(cRetFlags)

	info := g.SecContextInfoPartial{
		InitiatorName:       c.initiatorName,
		Flags:               ctxFlags,
		ExpiresAt:           timeRecToGssLifetime(cTimeRec),
		LocallyInitiated:    c.isInitiator,
		FullyEstablished:    !c.continueNeeded,
		ProtectionReady:     protFlag,
		Transferrable:       transFlag,
		DelegatedCredential: c.delegCred,
	}
	if cActualMech != C.GSS_C_NO_OID {
		mech, err := g.MechFromOid(oidFromGssOid(cActualMech))
		if err != nil {
			return nil, g.SecContextInfoPartial{}, fmt.Errorf("unknown mech returned from gss_accept_sec_context: %w", g.ErrBadMech)
		}
		info.Mech = mech
	}

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
	var cMinor C.OM_uint32
	var cOutToken C.gss_buffer_desc = C.gss_empty_buffer // allocated by GSSAPI;  released by *1
	cMajor := C.gss_delete_sec_context(&cMinor, &c.id, &cOutToken)

	// *1   Release GSSAPI allocated buffer
	defer C.gss_release_buffer(&cMinor, &cOutToken)

	c.id = nil
	outToken := C.GoBytes(cOutToken.value, C.int(cOutToken.length))

	return outToken, makeStatus(cMajor, cMinor)
}

// ProcessToken is used to process error tokens from the peero.  No idea how to test this!
func (c *SecContext) ProcessToken(token []byte) error {
	var cMinor C.OM_uint32
	cInputToken, pinner := bytesToCBuffer(token, nil)
	defer pinner.Unpin()

	cMajor := C.gss_process_context_token(&cMinor, c.id, &cInputToken)
	if cMajor != C.GSS_S_COMPLETE {
		return makeStatus(cMajor, cMinor)
	}

	return nil
}

func (c *SecContext) ExpiresAt() (*g.GssLifetime, error) {
	var cMinor C.OM_uint32
	var cTimeRec C.OM_uint32
	cMajor := C.gss_context_time(&cMinor, c.id, &cTimeRec)
	if cMajor != C.GSS_S_COMPLETE {
		return nil, makeStatus(cMajor, cMinor)
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

	var cMinor C.OM_uint32
	var cSrcName, cTargName C.gss_name_t = C.GSS_C_NO_NAME, C.GSS_C_NO_NAME // allocated by GSSAPI;  released by SecContext.Delete()
	var cLifetime, cFlags C.OM_uint32
	var cMechOid C.gss_OID = C.GSS_C_NO_OID // do not free, pointer to static value returned
	var cLocallyInitiated, cOpen C.int
	cMajor := C.gss_inquire_context(&cMinor, c.id, &cSrcName, &cTargName, &cLifetime, &cMechOid, &cFlags, &cLocallyInitiated, &cOpen)

	if cMajor != C.GSS_S_COMPLETE {
		return nil, makeStatus(cMajor, cMinor)
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
		if cMechOid == C.GSS_C_NO_OID && isMacGssapi() {
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
	var cMinor C.OM_uint32
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

	cMajor := C.gss_wrap_size_limit(&cMinor, c.id, cConfReq, C.gss_qop_t(qop), C.OM_uint32(maxWrapSize), &cMaxInputSize)
	if cMajor != C.GSS_S_COMPLETE {
		return 0, makeStatus(cMajor, cMinor)
	}

	// conversion is safe -- uint is either 32 or 64 bits here but cMaxInputSize is always 32 bit
	return uint(cMaxInputSize), nil
}

func (c *SecContext) Export() ([]byte, error) {
	var cMinor C.OM_uint32
	var cToken C.gss_buffer_desc = C.gss_empty_buffer // allocated by GSSAPI;  released by *1
	cMajor := C.gss_export_sec_context(&cMinor, &c.id, &cToken)
	if cMajor != 0 {
		return nil, makeStatus(cMajor, cMinor)
	}

	defer C.gss_release_buffer(&cMinor, &cToken) // *1  Release GSSAPI allocated buffer

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

	var cMinor C.OM_uint32
	var cConfReq, cConfState C.int
	var cOutputMessage C.gss_buffer_desc = C.gss_empty_buffer // allocated by GSSAPI;  released by *1
	if confReq {
		cConfReq = 1
	}

	cMajor := C.gss_wrap(&cMinor, c.id, cConfReq, C.gss_qop_t(qop), &cInputMessage, &cConfState, &cOutputMessage)
	if cMajor != C.GSS_S_COMPLETE {
		return nil, false, makeStatus(cMajor, cMinor)
	}

	defer C.gss_release_buffer(&cMinor, &cOutputMessage) // *1  Release GSSAPI allocated buffer

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

	var cMinor C.OM_uint32
	var cConfState C.int
	var cOutputMessage C.gss_buffer_desc = C.gss_empty_buffer // allocated by GSSAPI;  released by *1
	var cQoP C.gss_qop_t

	cMajor := C.gss_unwrap(&cMinor, c.id, &cInputMessage, &cOutputMessage, &cConfState, &cQoP)
	if cMajor != 0 {
		return nil, false, 0, makeStatus(cMajor, cMinor)
	}

	defer C.gss_release_buffer(&cMinor, &cOutputMessage) // *1  Release GSSAPI allocated buffer

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

	var cMinor C.OM_uint32
	var cMsgToken C.gss_buffer_desc = C.gss_empty_buffer // allocated by GSSAPI;  released by *1
	cMajor := C.gss_get_mic(&cMinor, c.id, C.gss_qop_t(qop), &cMessage, &cMsgToken)
	if cMajor != 0 {
		return nil, makeStatus(cMajor, cMinor)
	}

	defer C.gss_release_buffer(&cMinor, &cMsgToken) // *1  Release GSSAPI allocated buffer

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
	cToken, _ := bytesToCBuffer(token, pinner)

	var cMinor C.OM_uint32
	var cQoP C.gss_qop_t
	cMajor := C.gss_verify_mic(&cMinor, c.id, &cMessage, &cToken, &cQoP)
	return g.QoP(cQoP), makeStatus(cMajor, cMinor)
}
