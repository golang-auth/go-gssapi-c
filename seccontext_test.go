package gssapi

import (
	"os"
	"testing"

	g "github.com/golang-auth/go-gssapi/v3"
	"github.com/stretchr/testify/assert"
)

type testAssets struct {
	ktfileRack string
	ktfileRuin string
	ccfile     string
	lib        g.Provider

	saveVars saveVars
}

func mkTestAssets() *testAssets {
	ta := &testAssets{
		saveVars: newSaveVars("KRB5_KTNAME", "KRB5CCNAME"),
		lib:      New(),
	}

	ktName1, krName2, ccName, err := writeKrbCreds()
	if err != nil {
		panic(err)
	}

	ta.ktfileRack = ktName1
	ta.ktfileRuin = krName2
	ta.ccfile = ccName

	return ta
}

func (ta *testAssets) Free() {
	ta.saveVars.Restore()
	os.Remove(ta.ktfileRack)
	os.Remove(ta.ccfile)
}

// will prevent compilation if SecContext{} doesn't implement the interface
func TestSecContextInterface(t *testing.T) {
	s := SecContext{}
	var gsc g.SecContext = &s

	_ = gsc
}

func TestInitSecContext(t *testing.T) {
	assert := assert.New(t)

	ta := mkTestAssets()
	defer ta.Free()

	os.Setenv("KRB5_KTNAME", ta.ktfileRack)
	os.Setenv("KRB5CCNAME", "FILE:"+ta.ccfile)

	// InitSecContext with this name should work because the cred-cache has a ticket
	// for rack/foo.golang-auth.io@GOLANG-AUTH.IO
	name, err := ta.lib.ImportName("rack@foo.golang-auth.io", g.GSS_NT_HOSTBASED_SERVICE)
	assert.NoError(err)

	// no continue should be needed when we don't request mutual auth
	secCtx, outTok, err := ta.lib.InitSecContext(name)
	assert.NoError(err)
	assert.NotEmpty(outTok)
	assert.NotNil(secCtx)
	assert.False(secCtx.ContinueNeeded())

	// .. but should be needed if we do request mutual auth
	secCtx, outTok, err = ta.lib.InitSecContext(name, g.WithInitiatorFlags(g.ContextFlagMutual))
	assert.NoError(err)
	assert.NotEmpty(outTok)
	assert.NotNil(secCtx)
	assert.True(secCtx.ContinueNeeded())

	// This one should not work because the CC doesn't have a ticket for ruin/bar.golang-auth.io@GOLANG-AUTH.IO
	// and there are no KDCs defined that can get us a ticket
	name, err = ta.lib.ImportName("ruin@bar.golang-auth.io", g.GSS_NT_HOSTBASED_SERVICE)
	assert.NoError(err)

	_, _, err = ta.lib.InitSecContext(name)
	assert.Error(err)
	assert.Contains(err.Error(), "Cannot find KDC")
}

func TestAcceptSecContext(t *testing.T) {
	assert := assert.New(t)

	ta := mkTestAssets()
	defer ta.Free()

	os.Setenv("KRB5_KTNAME", ta.ktfileRack)
	os.Setenv("KRB5CCNAME", "FILE:"+ta.ccfile)

	// InitSecContext with this name should work because the cred-cache has a ticket
	// for rack/foo.golang-auth.io@GOLANG-AUTH.IO
	name, err := ta.lib.ImportName("rack@foo.golang-auth.io", g.GSS_NT_HOSTBASED_SERVICE)
	assert.NoError(err)

	secCtxInitiator, initiatorTok, err := ta.lib.InitSecContext(name)
	assert.NoError(err)
	assert.NotEmpty(initiatorTok)
	assert.NotNil(secCtxInitiator)
	assert.False(secCtxInitiator.ContinueNeeded())

	// the initiator token should be accepted by AcceptSecContext because we have a keytab
	// for the service princ.  The output token should be empty because the initiator
	// didn't request  mutual auth
	secCtxAcceptor, acceptorTok, err := ta.lib.AcceptSecContext(nil, initiatorTok, nil)
	assert.NoError(err)
	assert.Empty(acceptorTok)
	assert.NotNil(secCtxAcceptor)
	assert.False(secCtxAcceptor.ContinueNeeded())

	// if we're doing mutual auth we should get an output token from the acceptor but it
	// should not need another one back from the initiator
	secCtxInitiator, initiatorTok, err = ta.lib.InitSecContext(name, g.WithInitiatorFlags(g.ContextFlagMutual))
	assert.NoError(err)
	assert.NotEmpty(initiatorTok)
	assert.NotNil(secCtxInitiator)
	assert.True(secCtxInitiator.ContinueNeeded())

	secCtxAcceptor, acceptorTok, err = ta.lib.AcceptSecContext(nil, initiatorTok, nil)
	assert.NoError(err)
	assert.NotEmpty(acceptorTok)
	assert.NotNil(secCtxAcceptor)
	assert.False(secCtxAcceptor.ContinueNeeded())
}

func TestDeleteSecContext(t *testing.T) {
	assert := assert.New(t)

	ta := mkTestAssets()
	defer ta.Free()

	os.Setenv("KRB5_KTNAME", ta.ktfileRack)
	os.Setenv("KRB5CCNAME", "FILE:"+ta.ccfile)

	// This should work because the cred-cache has a ticket for rack/foo.golang-auth.io@GOLANG-AUTH.IO
	name, err := ta.lib.ImportName("rack@foo.golang-auth.io", g.GSS_NT_HOSTBASED_SERVICE)
	assert.NoError(err)

	secCtx, outTok, err := ta.lib.InitSecContext(name)
	assert.NoError(err)
	assert.NotEmpty(outTok)
	assert.NotNil(secCtx)

	// deleting a live or a deleted context should not return errors
	_, err = secCtx.Delete()
	assert.NoError(err)
	assert.Nil(secCtx.(*SecContext).id)

	_, err = secCtx.Delete()
	assert.NoError(err)
	assert.Nil(secCtx.(*SecContext).id)
}

func TestContextExpiresAt(t *testing.T) {
	assert := assert.New(t)

	ta := mkTestAssets()
	defer ta.Free()

	os.Setenv("KRB5_KTNAME", ta.ktfileRack)
	os.Setenv("KRB5CCNAME", "FILE:"+ta.ccfile)

	// This should work because the cred-cache has a ticket for rack/foo.golang-auth.io@GOLANG-AUTH.IO
	name, err := ta.lib.ImportName("rack@foo.golang-auth.io", g.GSS_NT_HOSTBASED_SERVICE)
	assert.NoError(err)

	secCtxInitiator, initiatorTok, err := ta.lib.InitSecContext(name)
	assert.NoError(err)
	assert.NotEmpty(initiatorTok)
	assert.NotNil(secCtxInitiator)
	assert.False(secCtxInitiator.ContinueNeeded())

	secCtxAcceptor, acceptorTok, err := ta.lib.AcceptSecContext(nil, initiatorTok, nil)
	assert.NoError(err)
	assert.Empty(acceptorTok)
	assert.NotNil(secCtxAcceptor)
	assert.False(secCtxAcceptor.ContinueNeeded())

	// both the initiator and the acceptor should know about the expiry time
	tm, err := secCtxInitiator.ExpiresAt()
	assert.NoError(err)
	assert.Equal(2051, tm.Year())

	tm, err = secCtxAcceptor.ExpiresAt()
	assert.NoError(err)
	assert.Equal(2051, tm.Year())
}

func TestContextWrapSizeLimit(t *testing.T) {
	assert := assert.New(t)

	ta := mkTestAssets()
	defer ta.Free()

	os.Setenv("KRB5CCNAME", "FILE:"+ta.ccfile)

	// This should work because the cred-cache has a ticket for rack/foo.golang-auth.io@GOLANG-AUTH.IO
	name, err := ta.lib.ImportName("rack@foo.golang-auth.io", g.GSS_NT_HOSTBASED_SERVICE)
	assert.NoError(err)

	o := g.WithInitiatorFlags(g.ContextFlagInteg | g.ContextFlagConf)

	secCtxInitiator, initiatorTok, err := ta.lib.InitSecContext(name, o)
	assert.NoError(err)
	assert.NotEmpty(initiatorTok)
	assert.NotNil(secCtxInitiator)
	assert.False(secCtxInitiator.ContinueNeeded())

	// the max unwrapped token size would always be less that the max
	// wrapped token size
	tokSize, err := secCtxInitiator.WrapSizeLimit(true, 100, 0)
	assert.NoError(err)
	assert.Less(tokSize, uint(1000))
}

func TestExportImportSecContext(t *testing.T) {
	assert := assert.New(t)

	ta := mkTestAssets()
	defer ta.Free()

	os.Setenv("KRB5CCNAME", "FILE:"+ta.ccfile)
	// This should work because the cred-cache has a ticket for rack/foo.golang-auth.io@GOLANG-AUTH.IO
	name, err := ta.lib.ImportName("rack@foo.golang-auth.io", g.GSS_NT_HOSTBASED_SERVICE)
	assert.NoError(err)
	secCtx, initiatorTok, err := ta.lib.InitSecContext(name)
	assert.NoError(err)
	assert.NotEmpty(initiatorTok)
	assert.NotNil(secCtx)
	assert.False(secCtx.ContinueNeeded())

	_, err = secCtx.Inquire() // should work the first time
	assert.NoError(err)

	tok, err := secCtx.Export() // exported context invalidates the original
	assert.NoError(err)
	assert.NotEmpty(tok)

	_, err = secCtx.Inquire() // so this should fail
	assert.ErrorIs(err, g.ErrNoContext)

	// try to import the context
	newCtx, err := ta.lib.ImportSecContext(tok)
	assert.NoError(err)
	_, err = newCtx.Inquire() // should work again here
	assert.NoError(err)

}

func TestSecContextEstablishment(t *testing.T) {
	assert := assert.New(t)

	ta := mkTestAssets()
	defer ta.Free()

	os.Setenv("KRB5_KTNAME", ta.ktfileRack)
	os.Setenv("KRB5CCNAME", "FILE:"+ta.ccfile)

	name, err := ta.lib.ImportName("rack@foo.golang-auth.io", g.GSS_NT_HOSTBASED_SERVICE)
	assert.NoError(err)

	secCtxInitiator, initiatorTok, err := ta.lib.InitSecContext(name, g.WithInitiatorFlags(g.ContextFlagMutual))
	assert.NoError(err)

	secCtxAcceptor, acceptorTok, err := ta.lib.AcceptSecContext(nil, initiatorTok, nil)
	assert.NoError(err)

	for secCtxInitiator.ContinueNeeded() {
		initiatorTok, err = secCtxInitiator.Continue(acceptorTok)
		assert.NoError(err)

		if len(initiatorTok) > 0 {
			acceptorTok, err = secCtxAcceptor.Continue(initiatorTok)
			assert.NoError(err)
		}
	}

	assert.False(secCtxAcceptor.ContinueNeeded())

	msg := []byte("Hello GSSAPI")
	wrapped, hasConf, err := secCtxInitiator.Wrap(msg, true, 0)
	assert.NoError(err)
	assert.True(hasConf)
	assert.NotEmpty(wrapped)

	unwrapped, hasConf, _, err := secCtxAcceptor.Unwrap(wrapped)
	assert.NoError(err)
	assert.True(hasConf)
	assert.Equal(msg, unwrapped)

	mic, err := secCtxInitiator.GetMIC(msg, 0)
	assert.NoError(err)
	assert.NotEmpty(mic)

	_, err = secCtxAcceptor.VerifyMIC(msg, mic)
	assert.NoError(err)
}

func TestChannelBindings(t *testing.T) {
	assert := assert.New(t)

	ta := mkTestAssets()
	defer ta.Free()

	hasChBound := hasChannelBound()
	if !hasChBound {
		t.Log("The GSSAPI C library does not support GSS_C_CHANNEL_BOUND_FLAG, ignoring related tests")
	}

	os.Setenv("KRB5_KTNAME", ta.ktfileRack)
	os.Setenv("KRB5CCNAME", "FILE:"+ta.ccfile)

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

			name, err := ta.lib.ImportName("rack@foo.golang-auth.io", g.GSS_NT_HOSTBASED_SERVICE)
			assert.NoError(err)
			defer name.Release()

			var reqFlags g.ContextFlag

			reqOpts := []g.InitSecContextOption{g.WithInitiatorFlags(reqFlags)}

			if tt.icb != nil {
				reqOpts = append(reqOpts, g.WithChannelBinding(tt.icb))
			}

			secCtxInitiator, initiatorTok, err := ta.lib.InitSecContext(name, reqOpts...)
			assert.NoError(err)
			assert.False(secCtxInitiator.ContinueNeeded())

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
