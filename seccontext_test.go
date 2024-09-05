package gssapi

import (
	"errors"
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

type testAssetType int

const (
	testKeytabRack testAssetType = 1 << iota
	testKeytabRuin
	testCredCache
)

func (ta *testAssets) useAsset(at testAssetType) {
	switch {
	default:
		os.Unsetenv("KRB5_KTNAME")
	case at&testKeytabRack > 0:
		os.Setenv("KRB5_KTNAME", ta.ktfileRack)
	case at&testKeytabRuin > 0:
		os.Setenv("KRB5_KTNAME", ta.ktfileRuin)
	}

	switch {
	default:
		os.Unsetenv("KRB5CCNAME")
	case at&testCredCache > 0:
		os.Setenv("KRB5CCNAME", "FILE:"+ta.ccfile)
	}
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

func initContextOne(provider g.Provider, name g.GssName, opts ...g.InitSecContextOption) (g.SecContext, []byte, error) {
	secCtx, err := provider.InitSecContext(name, opts...)
	if err != nil {
		return nil, nil, err
	}

	if secCtx == nil {
		return nil, nil, errors.New("nil sec ctx")
	}

	outTok, err := secCtx.Continue(nil)
	if err == nil && len(outTok) == 0 {
		err = errors.New("Empty first token")
	}

	ctx := secCtx.(*SecContext)
	if err == nil && ctx.id == nil {
		return nil, nil, errors.New("unexpected nil context")
	}

	return secCtx, outTok, err
}

func acceptContextOne(provider g.Provider, cred g.Credential, inTok []byte) (g.SecContext, []byte, error) {
	secCtx, err := provider.AcceptSecContext(cred)
	if err != nil {
		return nil, nil, err
	}

	if secCtx == nil {
		return nil, nil, errors.New("nil sec ctx")
	}

	outTok, err := secCtx.Continue(inTok)

	ctx := secCtx.(*SecContext)
	if err == nil && ctx.id == nil {
		return nil, nil, errors.New("unexpected nil context")
	}

	return secCtx, outTok, err
}

var ta *testAssets

func TestMain(m *testing.M) {
	ta = mkTestAssets()
	defer ta.Free()

	m.Run()
}

func TestInitSecContext(t *testing.T) {
	assert := assert.New(t)
	ta.useAsset(testCredCache)

	// InitSecContext with this name should work because the cred-cache has a ticket
	// for rack/foo.golang-auth.io@GOLANG-AUTH.IO
	name, err := ta.lib.ImportName("rack@foo.golang-auth.io", g.GSS_NT_HOSTBASED_SERVICE)
	assert.NoError(err)

	// no continue should be needed when we don't request mutual auth
	secCtx, outTok, err := initContextOne(ta.lib, name)
	assert.NoError(err)
	assert.NotNil(secCtx)
	assert.NotEmpty(outTok)
	assert.False(secCtx.ContinueNeeded())

	// .. but should be needed if we do request mutual auth
	secCtx, outTok, err = initContextOne(ta.lib, name, g.WithInitiatorFlags(g.ContextFlagMutual))
	assert.NoError(err)
	assert.NotNil(secCtx)
	assert.NotEmpty(outTok)
	assert.True(secCtx.ContinueNeeded())

	// This one should not work because the CC doesn't have a ticket for ruin/bar.golang-auth.io@GOLANG-AUTH.IO
	// and there are no KDCs defined that can get us a ticket
	name, err = ta.lib.ImportName("ruin@bar.golang-auth.io", g.GSS_NT_HOSTBASED_SERVICE)
	assert.NoError(err)

	_, _, err = initContextOne(ta.lib, name)
	assert.Error(err)
	if err != nil {
		assert.Contains(err.Error(), "Cannot find KDC")
	}
}

func TestAcceptSecContext(t *testing.T) {
	assert := assert.New(t)
	ta.useAsset(testCredCache | testKeytabRack)

	// InitSecContext with this name should work because the cred-cache has a ticket
	// for rack/foo.golang-auth.io@GOLANG-AUTH.IO
	name, err := ta.lib.ImportName("rack@foo.golang-auth.io", g.GSS_NT_HOSTBASED_SERVICE)
	assert.NoError(err)

	_, initiatorTok, err := initContextOne(ta.lib, name)
	assert.NoError(err)

	// the initiator token should be accepted by AcceptSecContext because we have a keytab
	// for the service princ.  The output token should be empty because the initiator
	// didn't request  mutual auth
	secCtxAcceptor, acceptorTok, err := acceptContextOne(ta.lib, nil, initiatorTok)
	assert.NoError(err)
	assert.Empty(acceptorTok)
	assert.NotNil(secCtxAcceptor)
	assert.False(secCtxAcceptor.ContinueNeeded())

	// if we're doing mutual auth we should get an output token from the acceptor but it
	// should not need another one back from the initiator
	_, initiatorTok, err = initContextOne(ta.lib, name, g.WithInitiatorFlags(g.ContextFlagMutual))
	assert.NoError(err)

	secCtxAcceptor, acceptorTok, err = acceptContextOne(ta.lib, nil, initiatorTok)
	assert.NoError(err)
	assert.NotEmpty(acceptorTok)
	assert.NotNil(secCtxAcceptor)
	assert.False(secCtxAcceptor.ContinueNeeded())
}

func TestDeleteSecContext(t *testing.T) {
	assert := assert.New(t)
	ta.useAsset(testCredCache)

	// This should work because the cred-cache has a ticket for rack/foo.golang-auth.io@GOLANG-AUTH.IO
	name, err := ta.lib.ImportName("rack@foo.golang-auth.io", g.GSS_NT_HOSTBASED_SERVICE)
	assert.NoError(err)

	secCtx, _, err := initContextOne(ta.lib, name)
	assert.NoError(err)

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
	ta.useAsset(testCredCache | testKeytabRack)

	// This should work because the cred-cache has a ticket for rack/foo.golang-auth.io@GOLANG-AUTH.IO
	name, err := ta.lib.ImportName("rack@foo.golang-auth.io", g.GSS_NT_HOSTBASED_SERVICE)
	assert.NoError(err)

	secCtxInitiator, initiatorTok, err := initContextOne(ta.lib, name)
	assert.NoError(err)

	secCtxAcceptor, _, err := acceptContextOne(ta.lib, nil, initiatorTok)
	assert.NoError(err)

	// both the initiator and the acceptor should know about the expiry time of the kerberos creds
	tm, err := secCtxInitiator.ExpiresAt()
	assert.NoError(err)
	assert.Equal(2051, tm.Year())

	tm, err = secCtxAcceptor.ExpiresAt()
	assert.NoError(err)
	assert.Equal(2051, tm.Year())
}

func TestContextWrapSizeLimit(t *testing.T) {
	assert := assert.New(t)
	ta.useAsset(testCredCache)

	// This should work because the cred-cache has a ticket for rack/foo.golang-auth.io@GOLANG-AUTH.IO
	name, err := ta.lib.ImportName("rack@foo.golang-auth.io", g.GSS_NT_HOSTBASED_SERVICE)
	assert.NoError(err)

	o := g.WithInitiatorFlags(g.ContextFlagInteg | g.ContextFlagConf)

	secCtxInitiator, _, err := initContextOne(ta.lib, name, o)
	assert.NoError(err)

	// the max unwrapped token size would always be less that the max
	// wrapped token size
	tokSize, err := secCtxInitiator.WrapSizeLimit(true, 100, 0)
	assert.NoError(err)
	assert.Less(tokSize, uint(1000))
}

func TestExportImportSecContext(t *testing.T) {
	assert := assert.New(t)
	ta.useAsset(testCredCache)

	// This should work because the cred-cache has a ticket for rack/foo.golang-auth.io@GOLANG-AUTH.IO
	name, err := ta.lib.ImportName("rack@foo.golang-auth.io", g.GSS_NT_HOSTBASED_SERVICE)
	assert.NoError(err)

	secCtx, _, err := initContextOne(ta.lib, name)
	assert.NoError(err)

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
	ta.useAsset(testCredCache | testKeytabRack)

	name, err := ta.lib.ImportName("rack@foo.golang-auth.io", g.GSS_NT_HOSTBASED_SERVICE)
	assert.NoError(err)

	secCtxInitiator, err := ta.lib.InitSecContext(name, g.WithInitiatorFlags(g.ContextFlagMutual))
	assert.NoError(err)

	secCtxAcceptor, err := ta.lib.AcceptSecContext(nil)
	assert.NoError(err)

	var initiatorTok, acceptorTok []byte
	for secCtxInitiator.ContinueNeeded() {
		acceptorTok, err = secCtxInitiator.Continue(initiatorTok)
		if err != nil {
			break
		}

		if len(acceptorTok) > 0 {
			initiatorTok, err = secCtxAcceptor.Continue(acceptorTok)
			if err != nil {
				break
			}
		}
	}

	assert.NoError(err)
	if err != nil {
		return
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
