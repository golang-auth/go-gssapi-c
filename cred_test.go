package gssapi

import (
	"os"
	"testing"
	"time"

	g "github.com/golang-auth/go-gssapi/v3"
	"github.com/stretchr/testify/assert"
)

func TestAcquireCredentialDefaultName(t *testing.T) {
	assert := assert.New(t)
	vars := newSaveVars("KRB5_KTNAME", "KRB5CCNAME")
	defer vars.Restore()

	lib := New()

	ktName, _, ccName, err := writeKrbCreds()
	assert.NoError(err)
	defer os.Remove(ktName)
	defer os.Remove(ccName)

	mechs := []g.GssMech{g.GSS_MECH_KRB5}

	// Try to acquire creds for initiate and accept when we only have a valid
	// keytab -- only 'accept' should work

	os.Setenv("KRB5_KTNAME", ktName)
	os.Setenv("KRB5CCNAME", "FILE:/tmp/no-such-file")

	_, err = lib.AcquireCredential(nil, mechs, g.CredUsageAcceptOnly, 0)
	assert.NoError(err)
	_, err = lib.AcquireCredential(nil, mechs, g.CredUsageInitiateOnly, 0)
	assert.Error(err)
	_, err = lib.AcquireCredential(nil, mechs, g.CredUsageInitiateAndAccept, 0)
	assert.Error(err)

	// Try again but only with a credentials cache -- only initiate should work
	os.Setenv("KRB5_KTNAME", "/tmp/no-such/file")
	os.Setenv("KRB5CCNAME", "FILE:"+ccName)

	_, err = lib.AcquireCredential(nil, mechs, g.CredUsageAcceptOnly, 0)
	assert.Error(err)
	_, err = lib.AcquireCredential(nil, mechs, g.CredUsageInitiateOnly, 0)
	assert.NoError(err)
	_, err = lib.AcquireCredential(nil, mechs, g.CredUsageInitiateAndAccept, 0)
	assert.Error(err)

	// Try again with a credentials cache and keytab -- both should work
	os.Setenv("KRB5_KTNAME", ktName)
	os.Setenv("KRB5CCNAME", "FILE:"+ccName)

	_, err = lib.AcquireCredential(nil, mechs, g.CredUsageAcceptOnly, 0)
	assert.NoError(err)
	_, err = lib.AcquireCredential(nil, mechs, g.CredUsageInitiateOnly, 0)
	assert.NoError(err)

	// Why doesn't Heimdal support acquiring default initiator and acceptor creds in the one call?
	if !IsHeimdal() {
		_, err = lib.AcquireCredential(nil, mechs, g.CredUsageInitiateAndAccept, 0)
		assert.NoError(err)
	}
}

func TestAcquireCredentialWithName(t *testing.T) {
	assert := assert.New(t)
	vars := newSaveVars("KRB5_KTNAME", "KRB5CCNAME")
	defer vars.Restore()

	lib := New()

	ktName, _, ccName, err := writeKrbCreds()
	assert.NoError(err)
	defer os.Remove(ktName)
	defer os.Remove(ccName)

	mechs := []g.GssMech{g.GSS_MECH_KRB5}

	nameInitiator, err := lib.ImportName(cliname, g.GSS_KRB5_NT_PRINCIPAL_NAME)
	assert.NoError(err)
	nameAcceptor, err := lib.ImportName(spname1, g.GSS_KRB5_NT_PRINCIPAL_NAME)
	assert.NoError(err)

	os.Setenv("KRB5_KTNAME", ktName)
	os.Setenv("KRB5CCNAME", "FILE:"+ccName)

	// Try to acquire creds for the initiator name -- should only work as
	// an initiator .. we don't have a keytab for the initiator
	_, err = lib.AcquireCredential(nameInitiator, mechs, g.CredUsageAcceptOnly, 0)
	assert.Error(err)
	_, err = lib.AcquireCredential(nameInitiator, mechs, g.CredUsageInitiateOnly, 0)
	assert.NoError(err)
	_, err = lib.AcquireCredential(nameInitiator, mechs, g.CredUsageInitiateAndAccept, 0)
	assert.Error(err)

	// Try to acquire for the acceptor name.. only work as an acceptor as we don't
	// have tickets for that name, only a keytab
	_, err = lib.AcquireCredential(nameAcceptor, mechs, g.CredUsageAcceptOnly, 0)
	assert.NoError(err)
	_, err = lib.AcquireCredential(nameAcceptor, mechs, g.CredUsageInitiateOnly, 0)
	assert.Error(err)
	_, err = lib.AcquireCredential(nameAcceptor, mechs, g.CredUsageInitiateAndAccept, 0)
	assert.Error(err)
}

func TestAcquireCredentialWithLifetime(t *testing.T) {
	assert := assert.New(t)
	vars := newSaveVars("KRB5_KTNAME", "KRB5CCNAME")
	defer vars.Restore()

	lib := New()

	ktName, _, ccName, err := writeKrbCreds()
	assert.NoError(err)
	defer os.Remove(ktName)
	defer os.Remove(ccName)

	mechs := []g.GssMech{g.GSS_MECH_KRB5}

	os.Setenv("KRB5_KTNAME", ktName)
	os.Setenv("KRB5CCNAME", "FILE:"+ccName)

	lifetime := time.Hour

	// We'll only get an expiry when requesting creds for the initiator, when it
	// is the expiry time of the TGT (sometime in 2032.. )

	_, err = lib.AcquireCredential(nil, mechs, g.CredUsageAcceptOnly, lifetime)
	assert.NoError(err)

	_, err = lib.AcquireCredential(nil, mechs, g.CredUsageInitiateOnly, lifetime)
	assert.NoError(err)

	if !IsHeimdal() {
		_, err = lib.AcquireCredential(nil, mechs, g.CredUsageInitiateAndAccept, lifetime)
		assert.NoError(err)
	}
}

func TestAcquireCredentialWithDefaultMech(t *testing.T) {
	assert := assert.New(t)
	vars := newSaveVars("KRB5_KTNAME", "KRB5CCNAME")
	defer vars.Restore()

	lib := New()

	ktName, _, ccName, err := writeKrbCreds()
	assert.NoError(err)
	defer os.Remove(ktName)
	defer os.Remove(ccName)

	os.Setenv("KRB5_KTNAME", ktName)
	os.Setenv("KRB5CCNAME", "FILE:"+ccName)

	_, err = lib.AcquireCredential(nil, nil, g.CredUsageAcceptOnly, 0)
	assert.NoError(err)

	_, err = lib.AcquireCredential(nil, nil, g.CredUsageInitiateOnly, 0)
	assert.NoError(err)

	if !IsHeimdal() {
		_, err = lib.AcquireCredential(nil, nil, g.CredUsageInitiateAndAccept, 0)
		assert.NoError(err)
	}
}

func TestAcquireCredentialMechResult(t *testing.T) {
	assert := assert.New(t)
	vars := newSaveVars("KRB5CCNAME")
	defer vars.Restore()

	lib := New()

	ktName, _, ccName, err := writeKrbCreds()
	assert.NoError(err)
	defer os.Remove(ktName)
	defer os.Remove(ccName)

	os.Setenv("KRB5CCNAME", "FILE:"+ccName)

	// Kerberos mech only
	mechs := []g.GssMech{g.GSS_MECH_KRB5}
	cred, err := lib.AcquireCredential(nil, mechs, g.CredUsageInitiateOnly, 0)
	assert.NoError(err)
	defer cred.Release() //nolint:errcheck

	// Kerb and SPNEGO
	mechs = []g.GssMech{g.GSS_MECH_KRB5, g.GSS_MECH_SPNEGO}
	cred, err = lib.AcquireCredential(nil, mechs, g.CredUsageInitiateOnly, 0)
	assert.NoError(err)
	defer cred.Release() //nolint:errcheck

}

func TestInquireCredential(t *testing.T) {
	assert := assert.New(t)
	vars := newSaveVars("KRB5CCNAME")
	defer vars.Restore()

	lib := New()

	ktName, _, ccName, err := writeKrbCreds()
	assert.NoError(err)
	defer os.Remove(ktName)
	defer os.Remove(ccName)

	os.Setenv("KRB5CCNAME", "FILE:"+ccName)

	// grab the default initiate cred -- which will be the TGT from the sample cred-cache
	cred, err := lib.AcquireCredential(nil, nil, g.CredUsageInitiateOnly, 0)
	assert.NoError(err)
	defer cred.Release() //nolint:errcheck

	info, err := cred.Inquire()
	assert.NoError(err)

	assert.Equal("robot@GOLANG-AUTH.IO", info.Name)
	assert.Equal(g.GSS_KRB5_NT_PRINCIPAL_NAME, info.NameType)
	assert.Equal(g.CredUsageInitiateOnly, info.Usage)
	assert.ElementsMatch([]g.GssMech{g.GSS_MECH_KRB5, g.GSS_MECH_SPNEGO}, info.Mechs)
	assert.Equal(2032, info.InitiatorExpiry.Year())
	assert.Nil(info.AcceptorExpiry)
}

func TestInquireCredentialByMech(t *testing.T) {
	assert := assert.New(t)
	vars := newSaveVars("KRB5CCNAME")
	defer vars.Restore()

	lib := New()

	ktName, _, ccName, err := writeKrbCreds()
	assert.NoError(err)
	defer os.Remove(ktName)
	defer os.Remove(ccName)

	os.Setenv("KRB5CCNAME", "FILE:"+ccName)

	// grab the default initiate cred -- which will be the TGT from the sample cred-cache
	cred, err := lib.AcquireCredential(nil, nil, g.CredUsageInitiateOnly, 0)
	assert.NoError(err)
	defer cred.Release() //nolint:errcheck

	info, err := cred.InquireByMech(g.GSS_MECH_KRB5)
	assert.NoError(err)

	assert.Equal("robot@GOLANG-AUTH.IO", info.Name)
	assert.Equal(g.GSS_KRB5_NT_PRINCIPAL_NAME, info.NameType)
	assert.Equal(g.CredUsageInitiateOnly, info.Usage)
	assert.ElementsMatch([]g.GssMech{g.GSS_MECH_KRB5}, info.Mechs)
	assert.Equal(2032, info.InitiatorExpiry.Year())
	assert.Equal(&time.Time{}, info.AcceptorExpiry)
}

func TestAddCredential(t *testing.T) {
	// this is broken in Heimdal
	if IsHeimdal() {
		t.SkipNow()
	}

	assert := assert.New(t)
	vars := newSaveVars("KRB5_KTNAME", "KRB5CCNAME")
	defer vars.Restore()

	lib := New()

	ktName, _, ccName, err := writeKrbCreds()
	assert.NoError(err)
	defer os.Remove(ktName)
	defer os.Remove(ccName)

	os.Setenv("KRB5CCNAME", "FILE:"+ccName)

	mechs := []g.GssMech{g.GSS_MECH_KRB5}

	// grab the default initiate cred -- which will be the TGT from the sample cred-cache
	cred, err := lib.AcquireCredential(nil, mechs, g.CredUsageInitiateOnly, 0)
	assert.NoError(err)
	defer cred.Release() //nolint:errcheck

	info, err := cred.Inquire()
	assert.NoError(err)
	assert.ElementsMatch([]g.GssMech{g.GSS_MECH_KRB5}, info.Mechs)

	// then try adding the SPNEGO mech
	err = cred.Add(nil, g.GSS_MECH_SPNEGO, g.CredUsageInitiateOnly, 0, 0)
	assert.NoError(err)

	info, err = cred.Inquire()
	assert.NoError(err)

	assert.ElementsMatch([]g.GssMech{g.GSS_MECH_KRB5, g.GSS_MECH_SPNEGO}, info.Mechs)
}
