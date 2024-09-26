package gssapi

import (
	"testing"

	g "github.com/golang-auth/go-gssapi/v3"
)

func TestMain(m *testing.M) {
	ta = mkTestAssets()
	defer ta.Free()

	m.Run()
}

// will prevent compilation if SecContext{} doesn't implement the interface
func TestSecContextInterface(t *testing.T) {
	s := SecContext{}
	var gsc g.SecContext = &s

	_ = gsc
}

func TestInitSecContext(t *testing.T) {
	assert := NewAssert(t)
	ta.useAsset(testCredCache)

	// InitSecContext with this name should work because the cred-cache has a ticket
	// for rack/foo.golang-auth.io@GOLANG-AUTH.IO
	name, err := ta.lib.ImportName("rack@foo.golang-auth.io", g.GSS_NT_HOSTBASED_SERVICE)
	assert.NoError(err)

	// no continue should be needed when we don't request mutual auth
	secCtx, outTok, err := ta.lib.InitSecContext(name)
	assert.NoError(err)
	if err == nil {
		assert.NotEmpty(outTok)
		assert.NotNil(secCtx)
		assert.False(secCtx.ContinueNeeded())
	}

	// .. but should be needed if we do request mutual auth
	secCtx, outTok, err = ta.lib.InitSecContext(name, g.WithInitiatorFlags(g.ContextFlagMutual))
	assert.NoError(err)
	if err == nil {
		assert.NotEmpty(outTok)
		assert.NotNil(secCtx)
		assert.True(secCtx.ContinueNeeded())
	}

	// This one should not work because the CC doesn't have a ticket for ruin/bar.golang-auth.io@GOLANG-AUTH.IO
	// and there are no KDCs defined that can get us a ticket
	name, err = ta.lib.ImportName("ruin@bar.golang-auth.io", g.GSS_NT_HOSTBASED_SERVICE)
	assert.NoErrorFatal(err)

	_, _, err = ta.lib.InitSecContext(name)
	assert.Error(err)
	if IsHeimdal() {
		assert.Contains(err.Error(), "unable to reach any KDC")
	} else {
		assert.Contains(err.Error(), "Cannot find KDC")
	}
}

func TestAcceptSecContext(t *testing.T) {
	assert := NewAssert(t)
	ta.useAsset(testCredCache | testKeytabRack)

	// InitSecContext with this name should work because the cred-cache has a ticket
	// for rack/foo.golang-auth.io@GOLANG-AUTH.IO
	name, err := ta.lib.ImportName("rack@foo.golang-auth.io", g.GSS_NT_HOSTBASED_SERVICE)
	assert.NoErrorFatal(err)

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

			secCtxInitiator, initiatorTok, err := ta.lib.InitSecContext(name, opts...)
			assert.NoErrorFatal(err)
			assert.Equal(secCtxInitiator.ContinueNeeded(), mutual)

			// the initiator token should be accepted by AcceptSecContext because we have a keytab
			// for the service princ.  The output token should be empty because the initiator
			// didn't request  mutual auth
			secCtxAcceptor, acceptorTok, err := ta.lib.AcceptSecContext(nil, initiatorTok, nil)
			assert.NoErrorFatal(err)
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

func TestDeleteSecContext(t *testing.T) {
	assert := NewAssert(t)
	ta.useAsset(testCredCache)

	// This should work because the cred-cache has a ticket for rack/foo.golang-auth.io@GOLANG-AUTH.IO
	name, err := ta.lib.ImportName("rack@foo.golang-auth.io", g.GSS_NT_HOSTBASED_SERVICE)
	assert.NoErrorFatal(err)

	secCtx, _, err := ta.lib.InitSecContext(name)
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
	assert := NewAssert(t)
	ta.useAsset(testCredCache | testKeytabRack)

	// This should work because the cred-cache has a ticket for rack/foo.golang-auth.io@GOLANG-AUTH.IO
	name, err := ta.lib.ImportName("rack@foo.golang-auth.io", g.GSS_NT_HOSTBASED_SERVICE)
	assert.NoErrorFatal(err)

	secCtxInitiator, initiatorTok, err := ta.lib.InitSecContext(name)
	assert.NoErrorFatal(err)

	secCtxAcceptor, _, err := ta.lib.AcceptSecContext(nil, initiatorTok, nil)
	assert.NoErrorFatal(err)

	// both the initiator and the acceptor should know about the expiry time
	tm, err := secCtxInitiator.ExpiresAt()
	assert.NoError(err)
	if err == nil {
		assert.Equal(2032, tm.Year())
	}

	tm, err = secCtxAcceptor.ExpiresAt()
	assert.NoError(err)
	if err == nil {
		assert.Equal(2032, tm.Year())
	}
}

func TestContextWrapSizeLimit(t *testing.T) {
	assert := NewAssert(t)
	ta.useAsset(testCredCache)

	// This should work because the cred-cache has a ticket for rack/foo.golang-auth.io@GOLANG-AUTH.IO
	name, err := ta.lib.ImportName("rack@foo.golang-auth.io", g.GSS_NT_HOSTBASED_SERVICE)
	assert.NoErrorFatal(err)

	o := g.WithInitiatorFlags(g.ContextFlagInteg | g.ContextFlagConf)

	secCtxInitiator, _, err := ta.lib.InitSecContext(name, o)
	assert.NoErrorFatal(err)

	// the max unwrapped token size would always be less that the max
	// wrapped token size
	tokSize, err := secCtxInitiator.WrapSizeLimit(true, 100, 0)
	assert.NoError(err)
	assert.Less(tokSize, uint(1000))
}

func TestExportImportSecContext(t *testing.T) {
	assert := NewAssert(t)
	ta.useAsset(testCredCache)

	// This should work because the cred-cache has a ticket for rack/foo.golang-auth.io@GOLANG-AUTH.IO
	name, err := ta.lib.ImportName("rack@foo.golang-auth.io", g.GSS_NT_HOSTBASED_SERVICE)
	assert.NoErrorFatal(err)

	secCtx, _, err := ta.lib.InitSecContext(name)
	assert.NoErrorFatal(err)

	_, err = secCtx.Inquire() // should work the first time
	assert.NoErrorFatal(err)

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
	ta.useAsset(testCredCache | testKeytabRack)

	name, err := ta.lib.ImportName("rack@foo.golang-auth.io", g.GSS_NT_HOSTBASED_SERVICE)
	assert.NoErrorFatal(err)

	secCtxInitiator, initiatorTok, err := ta.lib.InitSecContext(name, g.WithInitiatorFlags(g.ContextFlagMutual))
	assert.NoErrorFatal(err)

	secCtxAcceptor, acceptorTok, err := ta.lib.AcceptSecContext(nil, initiatorTok, nil)
	assert.NoErrorFatal(err)

	for secCtxInitiator.ContinueNeeded() {
		initiatorTok, err = secCtxInitiator.Continue(acceptorTok)
		assert.NoErrorFatal(err)

		if len(initiatorTok) > 0 {
			acceptorTok, err = secCtxAcceptor.Continue(initiatorTok)
			assert.NoErrorFatal(err)
		}
	}

	assert.False(secCtxAcceptor.ContinueNeeded())

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

	ta.useAsset(testCredCache | testKeytabRack)

	cb1 := g.ChannelBinding{Data: []byte("foo")}
	cb2 := g.ChannelBinding{Data: []byte("bar")}
	_ = cb2

	tests := []struct {
		name         string
		icb          *g.ChannelBinding
		acb          *g.ChannelBinding
		expectError  error
		expectCbFlag bool
	}{
		// neither side requests bindings: not an error and don't expect ContextFlagChannelBound return flag to be set
		{"no-bindings", nil, nil, nil, false},
		// only initiator requests bindings: not an error and don't expect ContextFlagChannelBound return flag to be set
		{"init-bindings-only", &cb1, nil, nil, false},
		// only acceptor requests bindings: not an error and don't expect ContextFlagChannelBound return flag to be set
		{"accept-bindings", nil, &cb1, nil, false},
		// both sides set matching bindings: not an error and DO expect ContextFlagChannelBound return flag to be set
		{"match-bindings", &cb1, &cb1, nil, true},
		// both sides set non-matching bindings: expect an error and don't expect ContextFlagChannelBound return flag to be set
		{"mismatch-bindings", &cb1, &cb2, g.ErrBadBindings, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := NewAssert(t)

			if tt.expectCbFlag && !hasChBound {
				t.SkipNow()
			}

			name, err := ta.lib.ImportName("rack@foo.golang-auth.io", g.GSS_NT_HOSTBASED_SERVICE)
			assert.NoErrorFatal(err)
			defer name.Release()

			var reqFlags g.ContextFlag

			reqOpts := []g.InitSecContextOption{g.WithInitiatorFlags(reqFlags)}

			if tt.icb != nil {
				reqOpts = append(reqOpts, g.WithChannelBinding(tt.icb))
			}

			_, initiatorTok, err := ta.lib.InitSecContext(name, reqOpts...)
			assert.NoErrorFatal(err)

			secCtxAcceptor, _, err := ta.lib.AcceptSecContext(nil, initiatorTok, tt.acb)
			if tt.expectError != nil {
				assert.ErrorIs(err, tt.expectError)
			} else {
				assert.NoError(err)
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
