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
	ta.useAsset(t, testKeytabRack|testNoCredCache)

	_, err = ta.lib.AcquireCredential(nil, mechs, g.CredUsageAcceptOnly, nil)
	assert.NoError(err)
	_, err = ta.lib.AcquireCredential(nil, mechs, g.CredUsageInitiateOnly, nil)
	assert.Error(err)
	_, err = ta.lib.AcquireCredential(nil, mechs, g.CredUsageInitiateAndAccept, nil)
	assert.Error(err)

	// Try again but only with a credentials cache -- only initiate should work
	ta.useAsset(t, testNoKeytab|testCredCache)

	_, err = ta.lib.AcquireCredential(nil, mechs, g.CredUsageAcceptOnly, nil)
	assert.Error(err)
	_, err = ta.lib.AcquireCredential(nil, mechs, g.CredUsageInitiateOnly, nil)
	assert.NoError(err)
	_, err = ta.lib.AcquireCredential(nil, mechs, g.CredUsageInitiateAndAccept, nil)
	assert.Error(err)

	// Try again with a credentials cache and keytab -- both should work
	ta.useAsset(t, testKeytabRack|testCredCache)

	_, err = ta.lib.AcquireCredential(nil, mechs, g.CredUsageAcceptOnly, nil)
	assert.NoError(err)
	_, err = ta.lib.AcquireCredential(nil, mechs, g.CredUsageInitiateOnly, nil)
	assert.NoError(err)

	// Why doesn't Heimdal support acquiring default initiator and acceptor creds in the one call?
	t.Run("initandaccept", func(t *testing.T) {
		assert := NewAssert(t)
		if isHeimdal() {
			t.Log("skipping acquire credential with initiate and accept on Heimdal")
			t.SkipNow()
		} else {
			_, err = ta.lib.AcquireCredential(nil, mechs, g.CredUsageInitiateAndAccept, nil)
			assert.NoError(err)
		}
	})
}

type someName struct{}

func (n *someName) Compare(other g.GssName) (bool, error) {
	return false, nil
}

func (n *someName) Display() (string, g.GssNameType, error) {
	return "", g.GSS_NO_NAME, nil
}

func (n *someName) Release() error {
	return nil
}

func (n *someName) InquireMechs() ([]g.GssMech, error) {
	return nil, nil
}

func (n *someName) Canonicalize(mech g.GssMech) (g.GssName, error) {
	return &someName{}, nil
}

func (n *someName) Export() ([]byte, error) {
	return nil, nil
}

func (n *someName) Duplicate() (g.GssName, error) {
	return &someName{}, nil
}

func TestAcquireCredentialWithForeignName(t *testing.T) {
	assert := NewAssert(t)
	n := &someName{}

	_, err := ta.lib.AcquireCredential(n, nil, g.CredUsageAcceptOnly, nil)
	assert.ErrorIs(err, g.ErrBadName)
}

func TestAcquireCredentialWithName(t *testing.T) {
	assert := NewAssert(t)

	ta.useAsset(t, testCredCache|testKeytabRack|testCfg1)

	mechs := []g.GssMech{g.GSS_MECH_KRB5}

	nameInitiator, err := ta.lib.ImportName(cliname, g.GSS_NT_USER_NAME)
	assert.NoErrorFatal(err)
	nameAcceptor, err := ta.lib.ImportName(spname1, g.GSS_KRB5_NT_PRINCIPAL_NAME)
	assert.NoErrorFatal(err)

	// Try to acquire creds for the initiator name -- should only work as
	// an initiator .. we don't have a keytab for the initiator
	_, err = ta.lib.AcquireCredential(nameInitiator, mechs, g.CredUsageAcceptOnly, nil)
	assert.Error(err)
	_, err = ta.lib.AcquireCredential(nameInitiator, mechs, g.CredUsageInitiateOnly, nil)
	assert.NoError(err)
	_, err = ta.lib.AcquireCredential(nameInitiator, mechs, g.CredUsageInitiateAndAccept, nil)
	assert.Error(err)

	// Try to acquire for the acceptor name.. should only work as an acceptor as we don't
	// have tickets for that name, only a keytab
	_, err = ta.lib.AcquireCredential(nameAcceptor, mechs, g.CredUsageAcceptOnly, nil)
	assert.NoError(err)
	_, err = ta.lib.AcquireCredential(nameAcceptor, mechs, g.CredUsageInitiateOnly, nil)
	assert.Error(err)
	_, err = ta.lib.AcquireCredential(nameAcceptor, mechs, g.CredUsageInitiateAndAccept, nil)
	assert.Error(err)
}

func TestAcquireCredentialWithLifetime(t *testing.T) {
	assert := NewAssert(t)

	var err error
	mechs := []g.GssMech{g.GSS_MECH_KRB5}

	ta.useAsset(t, testCredCache|testKeytabRack)

	lifetime := g.MakeGssLifetime(time.Hour)

	// We'll only get an expiry when requesting creds for the initiator, when it
	// is the expiry time of the TGT (sometime in 2032.. )

	_, err = ta.lib.AcquireCredential(nil, mechs, g.CredUsageAcceptOnly, lifetime)
	assert.NoError(err)

	_, err = ta.lib.AcquireCredential(nil, mechs, g.CredUsageInitiateOnly, lifetime)
	assert.NoError(err)

	t.Run("initandaccept", func(t *testing.T) {
		assert := NewAssert(t)
		if isHeimdal() {
			t.Log("skipping acquire credential with initiate and accept on Heimdal")
			t.SkipNow()
		} else {
			_, err = ta.lib.AcquireCredential(nil, mechs, g.CredUsageInitiateAndAccept, lifetime)
			assert.NoError(err)
		}
	})

}

func TestAcquireCredentialWithDefaultMech(t *testing.T) {
	assert := NewAssert(t)

	var err error
	ta.useAsset(t, testCredCache|testKeytabRack)

	_, err = ta.lib.AcquireCredential(nil, nil, g.CredUsageAcceptOnly, nil)
	assert.NoError(err)

	_, err = ta.lib.AcquireCredential(nil, nil, g.CredUsageInitiateOnly, nil)
	assert.NoError(err)

	t.Run("initandaccept", func(t *testing.T) {
		assert := NewAssert(t)
		if isHeimdal() {
			t.Log("skipping acquire credential with initiate and accept on Heimdal")
			t.SkipNow()
		} else {
			_, err = ta.lib.AcquireCredential(nil, nil, g.CredUsageInitiateAndAccept, nil)
			assert.NoError(err)
		}
	})

}

func TestAcquireCredentialMechResult(t *testing.T) {
	assert := NewAssert(t)
	var err error
	ta.useAsset(t, testCredCache)

	// Kerberos mech only
	mechs := []g.GssMech{g.GSS_MECH_KRB5}
	cred, err := ta.lib.AcquireCredential(nil, mechs, g.CredUsageInitiateOnly, nil)
	assert.NoError(err)
	defer func() {
		if cred != nil {
			_ = cred.Release()
		}
	}() //nolint:errcheck

	// Kerb and SPNEGO
	mechs = []g.GssMech{g.GSS_MECH_KRB5, g.GSS_MECH_SPNEGO}
	cred, err = ta.lib.AcquireCredential(nil, mechs, g.CredUsageInitiateOnly, nil)
	assert.NoError(err)
	defer func() {
		if cred != nil {
			_ = cred.Release()
		}
	}() //nolint:errcheck

}

func TestInquireCredentialAcceptor(t *testing.T) {
	assert := NewAssert(t)
	var err error
	ta.useAsset(t, testCredCache|testKeytabRack)

	// grab the default initiate cred -- which will be the TGT from the sample cred-cache
	cred, err := ta.lib.AcquireCredential(nil, nil, g.CredUsageAcceptOnly, nil)
	assert.NoErrorFatal(err)
	defer cred.Release() //nolint:errcheck

	info, err := cred.Inquire()
	assert.NoErrorFatal(err)

	assert.Equal(g.CredUsageAcceptOnly, info.Usage)

	if isMacGssapi() {
		assert.ElementsMatch([]g.GssMech{g.GSS_MECH_KRB5}, info.Mechs)
	} else {
		assert.ElementsMatch([]g.GssMech{g.GSS_MECH_KRB5, g.GSS_MECH_SPNEGO}, info.Mechs)
	}
	assert.Equal(g.GssLifetimeIndefinite, info.AcceptorExpiry.Status)
}

func TestInquireCredential(t *testing.T) {
	assert := NewAssert(t)
	var err error
	ta.useAsset(t, testCredCache|testNoKeytab)

	// grab the default initiate cred -- which will be the TGT from the sample cred-cache
	cred, err := ta.lib.AcquireCredential(nil, nil, g.CredUsageInitiateOnly, nil)
	assert.NoErrorFatal(err)
	defer cred.Release() //nolint:errcheck

	info, err := cred.Inquire()
	assert.NoErrorFatal(err)

	assert.Equal("robot@GOLANG-AUTH.IO", info.Name)
	assert.Equal(g.GSS_KRB5_NT_PRINCIPAL_NAME, info.NameType)

	assert.Equal(g.CredUsageInitiateOnly, info.Usage)

	if isMacGssapi() {
		assert.ElementsMatch([]g.GssMech{g.GSS_MECH_KRB5}, info.Mechs)
	} else {
		assert.ElementsMatch([]g.GssMech{g.GSS_MECH_KRB5, g.GSS_MECH_SPNEGO}, info.Mechs)
	}
	assert.Equal(g.GssLifetimeAvailable, info.InitiatorExpiry.Status)
	assert.Equal(2033, info.InitiatorExpiry.ExpiresAt.UTC().Year())
}

func TestInquireCredentiaAcceptorlByMech(t *testing.T) {
	assert := NewAssert(t)
	var err error
	ta.useAsset(t, testNoCredCache|testKeytabRack|testCfg1)

	cred, err := ta.lib.AcquireCredential(nil, nil, g.CredUsageAcceptOnly, nil)
	assert.NoErrorFatal(err)
	defer cred.Release() //nolint:errcheck

	info, err := cred.InquireByMech(g.GSS_MECH_KRB5)
	assert.NoErrorFatal(err)

	if isHeimdalAfter7() {
		// Later Heimdal versions don't return a name for the acceptor cred
		assert.Equal(g.GSS_NO_NAME, info.NameType)
	} else {
		assert.NotEmpty(info.Name)
		assert.Equal(g.GSS_KRB5_NT_PRINCIPAL_NAME, info.NameType)
	}
	assert.Equal(g.CredUsageAcceptOnly, info.Usage)
	assert.ElementsMatch([]g.GssMech{g.GSS_MECH_KRB5}, info.Mechs)
	assert.Equal(g.GssLifetimeIndefinite, info.AcceptorExpiry.Status)
}
func TestInquireCredentialByMech(t *testing.T) {
	assert := NewAssert(t)
	var err error
	ta.useAsset(t, testCredCache)

	// grab the default initiate cred -- which will be the TGT from the sample cred-cache
	cred, err := ta.lib.AcquireCredential(nil, nil, g.CredUsageInitiateOnly, nil)
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
	if isHeimdal() && !hasDuplicateCred() {
		t.Skip("skipping test in this version of Heimdal")
	}
	assert := NewAssert(t)
	var err error
	ta.useAsset(t, testCredCache|testKeytabAll)

	mechs := []g.GssMech{g.GSS_MECH_KRB5}

	// grab the default initiate cred -- which will be the TGT from the sample cred-cache
	cred, err := ta.lib.AcquireCredential(nil, mechs, g.CredUsageInitiateOnly, nil)
	assert.NoErrorFatal(err)
	defer cred.Release() //nolint:errcheck

	info, err := cred.Inquire()
	assert.NoErrorFatal(err)
	assert.Equal(g.CredUsageInitiateOnly, info.Usage)
	assert.ElementsMatch([]g.GssMech{g.GSS_MECH_KRB5}, info.Mechs)

	// then try adding the IAKRB mech
	_, err = cred.Add(nil, g.GSS_MECH_IAKERB, g.CredUsageAcceptOnly, nil, nil, true)
	assert.NoErrorFatal(err)

	info, err = cred.Inquire()
	assert.NoErrorFatal(err)
	assert.ElementsMatch([]g.GssMech{g.GSS_MECH_KRB5, g.GSS_MECH_IAKERB}, info.Mechs)
}

func TestAddCredentialWithName(t *testing.T) {
	if isHeimdal() && !hasDuplicateCred() {
		t.Skip("skipping test in this version of Heimdal")
	}

	assert := NewAssert(t)

	mechs := []g.GssMech{g.GSS_MECH_KRB5}
	ta.useAsset(t, testKeytabAll|testCredCache)

	rack, err := ta.lib.ImportName(spname1, g.GSS_KRB5_NT_PRINCIPAL_NAME)
	assert.NoErrorFatal(err)

	ruin, err := ta.lib.ImportName(spname2, g.GSS_KRB5_NT_PRINCIPAL_NAME)
	assert.NoErrorFatal(err)

	// grab the default acceptor cred
	cred, err := ta.lib.AcquireCredential(rack, mechs, g.CredUsageAcceptOnly, nil)
	assert.NoErrorFatal(err)
	defer cred.Release() //nolint:errcheck

	_, err = cred.Add(ruin, g.GSS_MECH_SPNEGO, g.CredUsageAcceptOnly, nil, nil, true)

	assert.NoErrorFatal(err)
	defer cred.Release() //nolint:errcheck
}

func TestHasDuplicateCred(t *testing.T) {
	assert := NewAssert(t)
	assert.Equal(hasDuplicateCred(), optionalSymbols["gss_duplicate_cred"] != nil)
}
