// SPDX-License-Identifier: Apache-2.0

package gssapi

import (
	"testing"

	g "github.com/golang-auth/go-gssapi/v3"
)

func TestLocalname(t *testing.T) {
	assert := NewAssert(t)

	ta.useAsset(t, testCredCache)

	targetName, err := ta.lib.ImportName("rack@foo.golang-auth.io", g.GSS_NT_HOSTBASED_SERVICE)
	assert.NoErrorFatal(err)
	defer releaseName(targetName)

	secCtxInitiator, _, _, err := initContextOne(ta.lib, targetName)
	assert.NoErrorFatal(err)
	defer secCtxInitiator.Delete() //nolint:errcheck

	info, err := secCtxInitiator.Inquire()
	assert.NoErrorFatal(err)

	nameLocal := info.InitiatorName.(g.GssNameExtLocalname)

	localname, err := nameLocal.Localname(g.GSS_MECH_KRB5)
	if ta.lib.HasExtension(g.HasExtLocalname) {
		assert.NoErrorFatal(err)
		assert.Equal("robot", localname)
	} else {
		assert.ErrorIs(err, g.ErrUnavailable)
	}
}

func TestInquireName(t *testing.T) {
	assert := NewAssert(t)

	// doest seem to be supported in Heimdal
	if isHeimdal() {
		t.Log("skipping inquire name on Heimdal")
		t.SkipNow()
	}

	ta.useAsset(t, testCredCache|testKeytabRack)

	targetName, err := ta.lib.ImportName("rack@foo.golang-auth.io", g.GSS_NT_HOSTBASED_SERVICE)
	assert.NoErrorFatal(err)
	defer func() { _ = targetName.Release() }()

	// imported names are not mechanism names unless imported from an exported name
	info, err := targetName.(*GssName).Inquire()
	assert.NoError(err)
	assert.False(info.IsMechName)
	assert.Empty(info.Attributes)

	// .. but the name returned from acceptSecContext is, plus it
	// should have attributes
	secCtxInitiator, initiatorTok, _, err := initContextOne(ta.lib, targetName)
	assert.NoErrorFatal(err)
	defer func() { _, _ = secCtxInitiator.Delete() }()

	secCtxAcceptor, _, _, err := acceptContextOne(ta.lib, nil, initiatorTok, nil)
	assert.NoErrorFatal(err)
	defer func() { _, _ = secCtxAcceptor.Delete() }()

	initiatorInfo, err := secCtxInitiator.Inquire()
	assert.NoErrorFatal(err)

	acceptorInfo, err := secCtxAcceptor.Inquire()
	assert.NoErrorFatal(err)

	info, err = initiatorInfo.InitiatorName.(*GssName).Inquire()
	assert.NoError(err)
	assert.True(info.IsMechName)
	assert.Equal(g.GSS_MECH_KRB5, info.Mech)

	info, err = acceptorInfo.InitiatorName.(*GssName).Inquire()
	assert.NoError(err)
	assert.True(info.IsMechName)
	assert.Equal(g.GSS_MECH_KRB5, info.Mech)
	assert.NotEmpty(info.Attributes)
}
