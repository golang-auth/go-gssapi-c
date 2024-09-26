//go:build !noextensions

package gssapi

import (
	"os"
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

	vars := newSaveVars("KRB5_CONFIG")
	defer vars.Restore()

	lib := New()

	f1, f2, err := writeKrb5Confs()
	assert.NoError(err)
	defer os.Remove(f1)
	defer os.Remove(f2)
	os.Setenv("KRB5_CONFIG", f1)

	name1, err := lib.ImportName("fooname", g.GSS_NT_USER_NAME)
	assert.NoErrorFatal(err)
	defer name1.Release() //nolint:errcheck

	isMN, _, err := name1.(*GssName).Inquire()
	assert.NoError(err)
	assert.False(isMN)

	// now canonicalize amd try again
	cName1, err := name1.Canonicalize(g.GSS_MECH_KRB5)
	assert.NoErrorFatal(err)

	isMN, _, err = cName1.(*GssName).Inquire()
	assert.NoError(err)
	assert.True(isMN)

}
