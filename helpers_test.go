package gssapi

import (
	"testing"

	g "github.com/golang-auth/go-gssapi/v3"
)

func TestOid2String(t *testing.T) {
	assert := NewAssert(t)

	oid := g.GSS_MECH_KRB5.Oid()
	oidString, err := oid2String(oid)
	assert.NoError(err)
	assert.Equal(g.GSS_MECH_KRB5.OidString(), oidString)
}
