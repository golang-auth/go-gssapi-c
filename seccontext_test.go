// SPDX-License-Identifier: Apache-2.0

package gssapi

import (
	"errors"
	"net"
	"testing"

	g "github.com/golang-auth/go-gssapi/v3"
)

// will prevent compilation if SecContext{} doesn't implement the interface
func TestSecContextInterface(t *testing.T) {
	s := SecContext{}
	var gsc g.SecContext = &s

	_ = gsc
}

func initContextOne(provider g.Provider, name g.GssName, opts ...g.InitSecContextOption) (g.SecContext, []byte, *g.SecContextInfoPartial, error) {
	secCtx, err := provider.InitSecContext(name, opts...)
	if err != nil {
		return nil, nil, nil, err
	}

	if secCtx == nil {
		return nil, nil, nil, errors.New("nil sec ctx")
	}

	outTok, info, err := secCtx.Continue(nil)
	if err == nil && len(outTok) == 0 {
		err = errors.New("Empty first token")
	}

	ctx := secCtx.(*SecContext)
	if err == nil && ctx.id == nil {
		return nil, nil, nil, errors.New("unexpected nil context")
	}

	return secCtx, outTok, &info, err
}

func acceptContextOne(provider g.Provider, cred g.Credential, inTok []byte, cb *g.ChannelBinding) (g.SecContext, []byte, *g.SecContextInfoPartial, error) {
	var opts []g.AcceptSecContextOption
	if cred != nil {
		opts = append(opts, g.WithAcceptorCredential(cred))
	}
	if cb != nil {
		opts = append(opts, g.WithAcceptorChannelBinding(cb))
	}
	secCtx, err := provider.AcceptSecContext(opts...)
	if err != nil {
		return nil, nil, nil, err
	}

	if secCtx == nil {
		return nil, nil, nil, errors.New("nil sec ctx")
	}

	outTok, info, err := secCtx.Continue(inTok)
	if err != nil {
		return nil, nil, nil, err
	}

	ctx := secCtx.(*SecContext)
	if err == nil && ctx.id == nil {
		return nil, nil, nil, errors.New("unexpected nil context")
	}

	return secCtx, outTok, &info, err
}

func TestInitSecContext(t *testing.T) {
	assert := NewAssert(t)
	ta.useAsset(t, testCredCache)

	// InitSecContext with this name should work because the cred-cache has a ticket
	// for rack/foo.golang-auth.io@GOLANG-AUTH.IO
	name, err := ta.lib.ImportName("rack@foo.golang-auth.io", g.GSS_NT_HOSTBASED_SERVICE)
	assert.NoError(err)
	defer name.Release() //nolint:errcheck

	// no continue should be needed when we don't request mutual auth
	secCtx, outTok, _, err := initContextOne(ta.lib, name)
	assert.NoError(err)
	defer secCtx.Delete() //nolint:errcheck
	if err == nil {
		assert.NotEmpty(outTok)
		assert.NotNil(secCtx)
		assert.False(secCtx.ContinueNeeded())
	}

	// .. but should be needed if we do request mutual auth
	secCtx, outTok, _, err = initContextOne(ta.lib, name, g.WithInitiatorFlags(g.ContextFlagMutual))
	assert.NoError(err)
	defer secCtx.Delete() //nolint:errcheck
	if err == nil {
		assert.NotEmpty(outTok)
		assert.NotNil(secCtx)
		assert.True(secCtx.ContinueNeeded())
	}

	// This one should not work because the CC doesn't have a ticket for ruin/bar.golang-auth.io@GOLANG-AUTH.IO
	// and there are no KDCs defined that can get us a ticket
	name, err = ta.lib.ImportName("ruin@bar.golang-auth.io", g.GSS_NT_HOSTBASED_SERVICE)
	assert.NoErrorFatal(err)
	defer name.Release() //nolint:errcheck

	_, _, _, err = initContextOne(ta.lib, name)
	assert.Error(err)
}

func TestInitSecContextBadParams(t *testing.T) {
	assert := NewAssert(t)
	ta.useAsset(t, testCredCache|testKeytabRack)

	badName := &someName{}

	_, err := ta.lib.InitSecContext(nil)
	assert.ErrorIs(err, g.ErrBadName)

	_, err = ta.lib.InitSecContext(badName)
	assert.ErrorIs(err, g.ErrBadName)
}

type someCredential struct{}

func (someCredential) Release() error {
	return nil
}

func (someCredential) Inquire() (*g.CredInfo, error) {
	return nil, nil
}

func (c someCredential) Add(name g.GssName, mech g.GssMech, usage g.CredUsage, initiatorLifetime *g.GssLifetime, acceptorLifetime *g.GssLifetime, mutate bool) (g.Credential, error) {
	return c, nil
}

func (someCredential) InquireByMech(mech g.GssMech) (*g.CredInfo, error) {
	return nil, nil
}

func TestInitSecContextWithCredential(t *testing.T) {
	assert := NewAssert(t)
	ta.useAsset(t, testCredCache)

	// InitSecContext with this name should work because the cred-cache has a ticket
	// for rack/foo.golang-auth.io@GOLANG-AUTH.IO
	name, err := ta.lib.ImportName("rack@foo.golang-auth.io", g.GSS_NT_HOSTBASED_SERVICE)
	assert.NoErrorFatal(err)
	defer name.Release() //nolint:errcheck

	// grab the default initiator credential
	cred, err := ta.lib.AcquireCredential(nil, nil, g.CredUsageInitiateOnly, nil)
	assert.NoErrorFatal(err)
	defer cred.Release() //nolint:errcheck

	secCtx, outTok, _, err := initContextOne(ta.lib, name, g.WithInitiatorCredential(cred))
	assert.NoError(err)
	defer secCtx.Delete() //nolint:errcheck
	if err == nil {
		assert.NotEmpty(outTok)
		assert.NotNil(secCtx)
		assert.False(secCtx.ContinueNeeded())
	}

	// test with a bad credential
	cred = &someCredential{}
	_, _, _, err = initContextOne(ta.lib, name, g.WithInitiatorCredential(cred))
	assert.ErrorIs(err, g.ErrDefectiveCredential)
}

func TestAcceptSecContext(t *testing.T) {
	assert := NewAssert(t)
	ta.useAsset(t, testCredCache|testKeytabRack)

	// InitSecContext with this name should work because the cred-cache has a ticket
	// for rack/foo.golang-auth.io@GOLANG-AUTH.IO
	name, err := ta.lib.ImportName("rack@foo.golang-auth.io", g.GSS_NT_HOSTBASED_SERVICE)
	assert.NoErrorFatal(err)
	defer name.Release() //nolint:errcheck

	for _, mutual := range []bool{true, false} {
		assert := NewAssert(t)

		tname := "No-Mutual"
		if mutual {
			tname = "Mutual-auth"
		}
		t.Run(tname, func(t *testing.T) {

			opts := []g.InitSecContextOption{}
			if mutual {
				opts = append(opts, g.WithInitiatorFlags(g.ContextFlagMutual))
			}

			secCtxInitiator, initiatorTok, _, err := initContextOne(ta.lib, name, opts...)
			assert.NoErrorFatal(err)
			defer secCtxInitiator.Delete() //nolint:errcheck
			assert.Equal(secCtxInitiator.ContinueNeeded(), mutual)

			// the initiator token should be accepted by AcceptSecContext because we have a keytab
			// for the service princ.  The output token should be empty because the initiator
			// didn't request  mutual auth
			secCtxAcceptor, acceptorTok, _, err := acceptContextOne(ta.lib, nil, initiatorTok, nil)
			assert.NoErrorFatal(err)
			defer secCtxAcceptor.Delete() //nolint:errcheck
			assert.NotNil(secCtxAcceptor)
			assert.False(secCtxAcceptor.ContinueNeeded())
			if mutual {
				assert.NotEmpty(acceptorTok)
			} else {
				assert.Empty(acceptorTok)
			}
		})
	}

}

func TestAcceptSecContextWithCredential(t *testing.T) {
	assert := NewAssert(t)
	//ta.useAsset(t, testCredCache|testKeytabRack)
	ta.useAsset(t, testCredCache|testKeytabRack)

	// InitSecContext with this name should work because the cred-cache has a ticket
	// for rack/foo.golang-auth.io@GOLANG-AUTH.IO
	name, err := ta.lib.ImportName("rack@foo.golang-auth.io", g.GSS_NT_HOSTBASED_SERVICE)
	assert.NoErrorFatal(err)
	defer name.Release() //nolint:errcheck

	// grab the default acceptor credential
	cred, err := ta.lib.AcquireCredential(nil, nil, g.CredUsageAcceptOnly, nil)
	assert.NoErrorFatal(err)
	defer cred.Release() //nolint:errcheck

	secCtxInitiator, initiatorTok, _, err := initContextOne(ta.lib, name)
	assert.NoErrorFatal(err)
	defer secCtxInitiator.Delete() //nolint:errcheck

	secCtxAcceptor, _, _, err := acceptContextOne(ta.lib, cred, initiatorTok, nil)
	assert.NoErrorFatal(err)
	defer secCtxAcceptor.Delete() //nolint:errcheck

	// test with a bad credential
	cred = &someCredential{}
	_, _, _, err = acceptContextOne(ta.lib, cred, initiatorTok, nil)
	assert.ErrorIs(err, g.ErrDefectiveCredential)

}

func TestDeleteSecContext(t *testing.T) {
	assert := NewAssert(t)
	ta.useAsset(t, testCredCache)

	// This should work because the cred-cache has a ticket for rack/foo.golang-auth.io@GOLANG-AUTH.IO
	name, err := ta.lib.ImportName("rack@foo.golang-auth.io", g.GSS_NT_HOSTBASED_SERVICE)
	assert.NoErrorFatal(err)
	defer name.Release() //nolint:errcheck

	secCtx, _, _, err := initContextOne(ta.lib, name)
	assert.NoErrorFatal(err)

	// deleting a live or a deleted context should not return errors
	_, err = secCtx.Delete()
	assert.NoError(err)
	assert.Nil(secCtx.(*SecContext).id)

	_, err = secCtx.Delete()
	assert.NoError(err)
	assert.Nil(secCtx.(*SecContext).id)
}

func TestContextExpiresAt(t *testing.T) {
	t.SkipNow()
	assert := NewAssert(t)
	ta.useAsset(t, testCredCache|testKeytabRack)

	// This should work because the cred-cache has a ticket for rack/foo.golang-auth.io@GOLANG-AUTH.IO
	name, err := ta.lib.ImportName("rack@foo.golang-auth.io", g.GSS_NT_HOSTBASED_SERVICE)
	assert.NoErrorFatal(err)
	defer name.Release() //nolint:errcheck

	secCtxInitiator, initiatorTok, _, err := initContextOne(ta.lib, name)
	assert.NoError(err)
	defer secCtxInitiator.Delete() //nolint:errcheck

	secCtxAcceptor, _, _, err := acceptContextOne(ta.lib, nil, initiatorTok, nil)
	assert.NoError(err)
	defer secCtxAcceptor.Delete() //nolint:errcheck

	// both the initiator and the acceptor should know about the expiry time of the kerberos creds
	tm, err := secCtxInitiator.ExpiresAt()
	assert.NoError(err)
	assert.Zero(tm.Status & g.GssLifetimeExpired)
	assert.Zero(tm.Status & g.GssLifetimeIndefinite)
	if err == nil {
		assert.Equal(2033, tm.ExpiresAt.UTC().Year())
	}

	tm, err = secCtxAcceptor.ExpiresAt()
	assert.NoError(err)
	assert.Zero(tm.Status & g.GssLifetimeExpired)
	assert.Zero(tm.Status & g.GssLifetimeIndefinite)
	if err == nil {
		assert.Equal(2033, tm.ExpiresAt.UTC().Year())
	}
}

func TestContextWrapSizeLimit(t *testing.T) {
	assert := NewAssert(t)
	ta.useAsset(t, testCredCache)

	// This should work because the cred-cache has a ticket for rack/foo.golang-auth.io@GOLANG-AUTH.IO
	name, err := ta.lib.ImportName("rack@foo.golang-auth.io", g.GSS_NT_HOSTBASED_SERVICE)
	assert.NoErrorFatal(err)
	defer name.Release() //nolint:errcheck

	o := g.WithInitiatorFlags(g.ContextFlagInteg | g.ContextFlagConf)

	secCtxInitiator, _, _, err := initContextOne(ta.lib, name, o)
	assert.NoError(err)
	defer secCtxInitiator.Delete() //nolint:errcheck

	// the max unwrapped token size would always be less that the max
	// wrapped token size
	tokSize, err := secCtxInitiator.WrapSizeLimit(true, 100, 0)
	assert.NoError(err)
	assert.Less(tokSize, uint(1000))
}

func TestExportImportSecContext(t *testing.T) {
	assert := NewAssert(t)
	ta.useAsset(t, testCredCache)

	// This should work because the cred-cache has a ticket for rack/foo.golang-auth.io@GOLANG-AUTH.IO
	name, err := ta.lib.ImportName("rack@foo.golang-auth.io", g.GSS_NT_HOSTBASED_SERVICE)
	assert.NoErrorFatal(err)
	defer name.Release() //nolint:errcheck

	secCtx, _, _, err := initContextOne(ta.lib, name)
	assert.NoErrorFatal(err)
	defer secCtx.Delete() //nolint:errcheck

	info, err := secCtx.Inquire() // should work the first time
	assert.NoErrorFatal(err)
	_ = info

	tok, err := secCtx.Export() // exported context invalidates the original
	assert.NoError(err)
	if err != nil {
		assert.FailNow(err.Error())
	}
	assert.NotEmpty(tok)

	_, err = secCtx.Inquire() // so this should fail
	assert.ErrorIs(err, g.ErrNoContext)

	// try to import the context
	newCtx, err := ta.lib.ImportSecContext(tok)
	assert.NoError(err)
	if err == nil {
		_, err = newCtx.Inquire() // should work again here
		assert.NoError(err)
	}

}

func TestSecContextEstablishment(t *testing.T) {
	assert := NewAssert(t)
	ta.useAsset(t, testCredCache|testKeytabRack)

	name, err := ta.lib.ImportName("rack@foo.golang-auth.io", g.GSS_NT_HOSTBASED_SERVICE)
	assert.NoErrorFatal(err)

	secCtxInitiator, err := ta.lib.InitSecContext(name, g.WithInitiatorFlags(g.ContextFlagMutual))
	assert.NoErrorFatal(err)

	secCtxAcceptor, err := ta.lib.AcceptSecContext()
	assert.NoErrorFatal(err)

	var initiatorTok, acceptorTok []byte
	for secCtxInitiator.ContinueNeeded() || secCtxAcceptor.ContinueNeeded() {
		acceptorTok, _, err = secCtxInitiator.Continue(initiatorTok)
		if err != nil {
			break
		}

		if len(acceptorTok) > 0 {
			initiatorTok, _, err = secCtxAcceptor.Continue(acceptorTok)
			if err != nil {
				break
			}
		}
	}

	assert.NoErrorFatal(err)
	if err != nil {
		return
	}

	msg := []byte("Hello GSSAPI")
	wrapped, hasConf, err := secCtxInitiator.Wrap(msg, true, 0)
	assert.NoErrorFatal(err)
	assert.True(hasConf)
	assert.NotEmpty(wrapped)

	unwrapped, hasConf, _, err := secCtxAcceptor.Unwrap(wrapped)
	assert.NoErrorFatal(err)
	assert.True(hasConf)
	assert.Equal(msg, unwrapped)

	mic, err := secCtxInitiator.GetMIC(msg, 0)
	assert.NoErrorFatal(err)
	assert.NotEmpty(mic)

	_, err = secCtxAcceptor.VerifyMIC(msg, mic)
	assert.NoErrorFatal(err)
}

func TestChannelBindings(t *testing.T) {

	hasChBound := hasChannelBound()
	if !hasChBound {
		t.Log("The GSSAPI C library does not support GSS_C_CHANNEL_BOUND_FLAG, ignoring related tests")
	}

	ta.useAsset(t, testCredCache|testKeytabRack|testCfg1)

	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}
	cb1 := g.ChannelBinding{InitiatorAddr: addr, AcceptorAddr: addr, Data: []byte("foo")}
	cb2 := g.ChannelBinding{InitiatorAddr: addr, AcceptorAddr: addr, Data: []byte("bar")}

	type testData struct {
		name         string
		icb          *g.ChannelBinding
		acb          *g.ChannelBinding
		expectError  error
		expectCbFlag bool
	}
	tests := []testData{
		// neither side requests bindings: not an error and don't expect ContextFlagChannelBound return flag to be set
		{"no-bindings", nil, nil, nil, false},
		// only initiator requests bindings: not an error and don't expect ContextFlagChannelBound return flag to be set
		{"init-bindings-only", &cb1, nil, nil, false},
		// only acceptor requests bindings: not an error and don't expect ContextFlagChannelBound return flag to be set
		{"accept-bindings", nil, &cb1, nil, false},
		// both sides set matching bindings: not an error and DO expect ContextFlagChannelBound return flag to be set
		{"match-bindings", &cb1, &cb1, nil, true},
	}

	// Channel bindings seem to be broken on MacOS Kerberos
	if !isMacGssapi() {
		tests = append(tests, testData{
			// both sides set non-matching bindings: expect an error and don't expect ContextFlagChannelBound return flag to be set
			"mismatch-bindings", &cb1, &cb2, g.ErrBadBindings, false,
		})
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := NewAssert(t)

			if tt.expectCbFlag && !hasChBound {
				t.SkipNow()
			}

			name, err := ta.lib.ImportName("rack@foo.golang-auth.io", g.GSS_NT_HOSTBASED_SERVICE)
			assert.NoErrorFatal(err)
			defer name.Release() //nolint:errcheck,

			var reqFlags g.ContextFlag

			reqOpts := []g.InitSecContextOption{g.WithInitiatorFlags(reqFlags)}

			if tt.icb != nil {
				reqOpts = append(reqOpts, g.WithInitiatorChannelBinding(tt.icb))
			}

			initSecCtx, initiatorTok, _, err := initContextOne(ta.lib, name, reqOpts...)
			assert.NoErrorFatal(err)
			defer initSecCtx.Delete() //nolint:errcheck

			secCtxAcceptor, _, _, err := acceptContextOne(ta.lib, nil, initiatorTok, tt.acb)
			defer func() {
				if secCtxAcceptor != nil {
					_, _ = secCtxAcceptor.Delete() //nolint:errcheck
				}
			}()

			if tt.expectError != nil {
				assert.ErrorIs(err, tt.expectError)
			} else {
				assert.NoErrorFatal(err)
				assert.False(secCtxAcceptor.ContinueNeeded())

				if hasChBound {
					info2, err := secCtxAcceptor.Inquire()
					assert.NoError(err)

					assert.Equal(tt.expectCbFlag, info2.Flags&g.ContextFlagChannelBound > 0)
				}
			}
		})
	}
}
