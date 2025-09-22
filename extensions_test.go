//go:build !noextensions

// SPDX-License-Identifier: Apache-2.0

package gssapi

import (
	"testing"

	g "github.com/golang-auth/go-gssapi/v3"
)

func TestInquireName(t *testing.T) {
	assert := NewAssert(t)

	// doest seem to work in Heimdal
	if isHeimdal() {
		t.Log("skipping inquire name on Heimdal")
		t.SkipNow()
	}

	ta.useAsset(testCredCache | testKeytabRack)

	targetName, err := ta.lib.ImportName("rack@foo.golang-auth.io", g.GSS_NT_HOSTBASED_SERVICE)
	assert.NoErrorFatal(err)
	defer func() { _ = targetName.Release() }()

	// imported names are not mechanism names unless imported from an exported name
	isMN, attrs, err := targetName.(*GssName).Inquire()
	assert.NoError(err)
	assert.False(isMN)
	assert.Empty(attrs)

	// .. but the name returned from acceptSecContest is, plus it
	// should have attributes
	secCtxInitiator, initiatorTok, err := initContextOne(ta.lib, targetName)
	assert.NoErrorFatal(err)
	defer func() { _, _ = secCtxInitiator.Delete() }()

	secCtxAcceptor, _, err := acceptContextOne(ta.lib, nil, initiatorTok, nil)
	assert.NoErrorFatal(err)
	defer func() { _, _ = secCtxAcceptor.Delete() }()

	initiatorInfo, err := secCtxInitiator.Inquire()
	assert.NoErrorFatal(err)

	acceptorInfo, err := secCtxAcceptor.Inquire()
	assert.NoErrorFatal(err)

	isMN, _, err = initiatorInfo.InitiatorName.(*GssName).Inquire()
	assert.NoError(err)
	assert.True(isMN)

	isMN, attrs, err = acceptorInfo.InitiatorName.(*GssName).Inquire()
	assert.NoError(err)
	assert.True(isMN)
	assert.NotEmpty(attrs)
}
