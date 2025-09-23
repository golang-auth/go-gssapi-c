// SPDX-License-Identifier: Apache-2.0

package gssapi

import (
	"testing"
	"time"

	g "github.com/golang-auth/go-gssapi/v3"
)

func TestAcquireCredentialDefaultName(t *testing.T) {
	assert := NewAssert(t)

	var err error
	mechs := []g.GssMech{g.GSS_MECH_KRB5}

	// Try to acquire creds for initiate and accept when we only have a valid
	// keytab -- only 'accept' should work
	ta.useAsset(testKeytabRack | testNoCredCache)

	_, err = ta.lib.AcquireCredential(nil, mechs, g.CredUsageAcceptOnly, 0)
	assert.NoError(err)
	_, err = ta.lib.AcquireCredential(nil, mechs, g.CredUsageInitiateOnly, 0)
	assert.Error(err)
	_, err = ta.lib.AcquireCredential(nil, mechs, g.CredUsageInitiateAndAccept, 0)
	assert.Error(err)

	// Try again but only with a credentials cache -- only initiate should work
	ta.useAsset(testNoKeytab | testCredCache)

	_, err = ta.lib.AcquireCredential(nil, mechs, g.CredUsageAcceptOnly, 0)
	assert.Error(err)
	_, err = ta.lib.AcquireCredential(nil, mechs, g.CredUsageInitiateOnly, 0)
	assert.NoError(err)
	_, err = ta.lib.AcquireCredential(nil, mechs, g.CredUsageInitiateAndAccept, 0)
	assert.Error(err)

	// Try again with a credentials cache and keytab -- both should work
	ta.useAsset(testKeytabRack | testCredCache)

	_, err = ta.lib.AcquireCredential(nil, mechs, g.CredUsageAcceptOnly, 0)
	assert.NoError(err)
	_, err = ta.lib.AcquireCredential(nil, mechs, g.CredUsageInitiateOnly, 0)
	assert.NoError(err)

	// Why doesn't Heimdal support acquiring default initiator and acceptor creds in the one call?
	if !isHeimdal() {
		_, err = ta.lib.AcquireCredential(nil, mechs, g.CredUsageInitiateAndAccept, 0)
		assert.NoError(err)
	}
}

func TestAcquireCredentialWithName(t *testing.T) {
	assert := NewAssert(t)

	ta.useAsset(testCredCache | testKeytabRack | testCfg1)

	mechs := []g.GssMech{g.GSS_MECH_KRB5}

	nameInitiator, err := ta.lib.ImportName(cliname, g.GSS_NT_USER_NAME)
	assert.NoErrorFatal(err)
	nameAcceptor, err := ta.lib.ImportName(spname1, g.GSS_KRB5_NT_PRINCIPAL_NAME)
	assert.NoErrorFatal(err)

	// Try to acquire creds for the initiator name -- should only work as
	// an initiator .. we don't have a keytab for the initiator
	_, err = ta.lib.AcquireCredential(nameInitiator, mechs, g.CredUsageAcceptOnly, 0)
	assert.Error(err)
	_, err = ta.lib.AcquireCredential(nameInitiator, mechs, g.CredUsageInitiateOnly, 0)
	assert.NoError(err)
	_, err = ta.lib.AcquireCredential(nameInitiator, mechs, g.CredUsageInitiateAndAccept, 0)
	assert.Error(err)

	// Try to acquire for the acceptor name.. should only work as an acceptor as we don't
	// have tickets for that name, only a keytab
	_, err = ta.lib.AcquireCredential(nameAcceptor, mechs, g.CredUsageAcceptOnly, 0)
	assert.NoError(err)
	_, err = ta.lib.AcquireCredential(nameAcceptor, mechs, g.CredUsageInitiateOnly, 0)
	assert.Error(err)
	_, err = ta.lib.AcquireCredential(nameAcceptor, mechs, g.CredUsageInitiateAndAccept, 0)
	assert.Error(err)
}

func TestAcquireCredentialWithLifetime(t *testing.T) {
	assert := NewAssert(t)

	var err error
	mechs := []g.GssMech{g.GSS_MECH_KRB5}

	ta.useAsset(testCredCache | testKeytabRack)

	lifetime := time.Hour

	// We'll only get an expiry when requesting creds for the initiator, when it
	// is the expiry time of the TGT (sometime in 2032.. )

	_, err = ta.lib.AcquireCredential(nil, mechs, g.CredUsageAcceptOnly, lifetime)
	assert.NoError(err)

	_, err = ta.lib.AcquireCredential(nil, mechs, g.CredUsageInitiateOnly, lifetime)
	assert.NoError(err)

	if !isHeimdal() {
		_, err = ta.lib.AcquireCredential(nil, mechs, g.CredUsageInitiateAndAccept, lifetime)
		assert.NoError(err)
	}
}

func TestAcquireCredentialWithDefaultMech(t *testing.T) {
	assert := NewAssert(t)

	var err error
	ta.useAsset(testCredCache | testKeytabRack)

	_, err = ta.lib.AcquireCredential(nil, nil, g.CredUsageAcceptOnly, 0)
	assert.NoError(err)

	_, err = ta.lib.AcquireCredential(nil, nil, g.CredUsageInitiateOnly, 0)
	assert.NoError(err)

	if !isHeimdal() {
		_, err = ta.lib.AcquireCredential(nil, nil, g.CredUsageInitiateAndAccept, 0)
		assert.NoError(err)
	}
}

func TestAcquireCredentialMechResult(t *testing.T) {
	assert := NewAssert(t)
	var err error
	ta.useAsset(testCredCache)

	// Kerberos mech only
	mechs := []g.GssMech{g.GSS_MECH_KRB5}
	cred, err := ta.lib.AcquireCredential(nil, mechs, g.CredUsageInitiateOnly, 0)
	assert.NoError(err)
	defer cred.Release() //nolint:errcheck

	// Kerb and SPNEGO
	mechs = []g.GssMech{g.GSS_MECH_KRB5, g.GSS_MECH_SPNEGO}
	cred, err = ta.lib.AcquireCredential(nil, mechs, g.CredUsageInitiateOnly, 0)
	assert.NoError(err)
	defer cred.Release() //nolint:errcheck

}

func TestInquireCredential(t *testing.T) {
	assert := NewAssert(t)
	var err error
	ta.useAsset(testCredCache)

	// grab the default initiate cred -- which will be the TGT from the sample cred-cache
	cred, err := ta.lib.AcquireCredential(nil, nil, g.CredUsageInitiateOnly, 0)
	assert.NoErrorFatal(err)
	defer cred.Release() //nolint:errcheck

	info, err := cred.Inquire()
	assert.NoErrorFatal(err)

	assert.Equal("robot@GOLANG-AUTH.IO", info.Name)
	assert.Equal(g.GSS_KRB5_NT_PRINCIPAL_NAME, info.NameType)
	assert.Equal(g.CredUsageInitiateOnly, info.Usage)
	assert.ElementsMatch([]g.GssMech{g.GSS_MECH_KRB5, g.GSS_MECH_SPNEGO}, info.Mechs)
	assert.Equal(g.GssLifetimeAvailable, info.InitiatorExpiry.Status)
	assert.Equal(2033, info.InitiatorExpiry.ExpiresAt.UTC().Year())
}

func TestInquireCredentialByMech(t *testing.T) {
	assert := NewAssert(t)
	var err error
	ta.useAsset(testCredCache)

	// grab the default initiate cred -- which will be the TGT from the sample cred-cache
	cred, err := ta.lib.AcquireCredential(nil, nil, g.CredUsageInitiateOnly, 0)
	assert.NoErrorFatal(err)
	defer cred.Release() //nolint:errcheck

	info, err := cred.InquireByMech(g.GSS_MECH_KRB5)
	assert.NoErrorFatal(err)

	assert.Equal("robot@GOLANG-AUTH.IO", info.Name)
	assert.Equal(g.GSS_KRB5_NT_PRINCIPAL_NAME, info.NameType)
	assert.Equal(g.CredUsageInitiateOnly, info.Usage)
	assert.ElementsMatch([]g.GssMech{g.GSS_MECH_KRB5}, info.Mechs)
	assert.Equal(g.GssLifetimeAvailable, info.InitiatorExpiry.Status)
	assert.Equal(2033, info.InitiatorExpiry.ExpiresAt.UTC().Year())
}

func TestAddCredentialInitiator(t *testing.T) {
	// this is broken in Heimdal
	if isHeimdal() {
		t.SkipNow()
	}

	assert := NewAssert(t)
	var err error
	ta.useAsset(testCredCache)

	mechs := []g.GssMech{g.GSS_MECH_KRB5}

	// grab the default initiate cred -- which will be the TGT from the sample cred-cache
	cred, err := ta.lib.AcquireCredential(nil, mechs, g.CredUsageInitiateOnly, 0)
	assert.NoErrorFatal(err)
	defer cred.Release() //nolint:errcheck

	info, err := cred.Inquire()
	assert.NoErrorFatal(err)
	assert.ElementsMatch([]g.GssMech{g.GSS_MECH_KRB5}, info.Mechs)

	// then try adding the SPNEGO mech
	err = cred.Add(nil, g.GSS_MECH_SPNEGO, g.CredUsageInitiateOnly, 0, 0)
	assert.NoError(err)

	info, err = cred.Inquire()
	assert.NoErrorFatal(err)

	assert.ElementsMatch([]g.GssMech{g.GSS_MECH_KRB5, g.GSS_MECH_SPNEGO}, info.Mechs)
}

func TestAddCredentialWithName(t *testing.T) {
	assert := NewAssert(t)

	mechs := []g.GssMech{g.GSS_MECH_KRB5}

	ruin, err := ta.lib.ImportName(spname2, g.GSS_KRB5_NT_PRINCIPAL_NAME)
	assert.NoErrorFatal(err)

	// grab the default acceptor cred
	//	ta.useAsset(testKeytabRack)
	ta.useAsset(testKeytabRack)
	cred, err := ta.lib.AcquireCredential(nil, mechs, g.CredUsageAcceptOnly, 0)
	assert.NoErrorFatal(err)
	defer cred.Release() //nolint:errcheck

	ta.useAsset(testKeytabRuin)
	err = cred.Add(ruin, g.GSS_MECH_SPNEGO, g.CredUsageAcceptOnly, 0, 0)
	assert.NoErrorFatal(err)
	defer cred.Release() //nolint:errcheck

}
