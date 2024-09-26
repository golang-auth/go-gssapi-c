//go:build !noextensions

package gssapi

import (
	"testing"

	g "github.com/golang-auth/go-gssapi/v3"
)

func TestInquireName(t *testing.T) {
	assert := NewAssert(t)

	// doest seem to work in Heimdal
	if IsHeimdal() {
		t.Log("skipping inquire name on Heimdal")
		t.SkipNow()
	}

	ta.useAsset(testCfg1)

	name1, err := ta.lib.ImportName("fooname", g.GSS_NT_USER_NAME)
	assert.NoErrorFatal(err)
	defer name1.Release() //nolint:errcheck

	// imported names are not mechanism names unless imported from an exported name
	isMN, _, err := name1.(*GssName).Inquire()
	assert.NoError(err)
	assert.False(isMN)

	// now canonicalize amd try again - this should make it a mechanism name
	cName1, err := name1.Canonicalize(g.GSS_MECH_KRB5)
	assert.NoErrorFatal(err)

	isMN, _, err = cName1.(*GssName).Inquire()
	assert.NoError(err)
	assert.True(isMN)

}
