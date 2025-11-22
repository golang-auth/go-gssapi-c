package gssapi

import (
	"testing"
	"unsafe"

	g "github.com/golang-auth/go-gssapi/v3"
)

func TestOidSet(t *testing.T) {
	assert := NewAssert(t)

	oids := []g.Oid{}

	// test with no OIDs
	oidSet, err := newOidSet(oids)
	assert.NoError(err)
	assert.NotNil(oidSet)

	mechs := []g.GssMech{g.GSS_MECH_KRB5, g.GSS_MECH_IAKERB}

	// Test with some OIDs
	oids = append(oids, mechs[0].Oid(), mechs[1].Oid())
	oidSet, err = newOidSet(oids)
	assert.NoErrorFatal(err)
	assert.NotNil(oidSet)

	if oidSet != nil {
		assert.Equal(2, int(oidSet.oidSet.count))

		elms := oidSet.oidSet.elements
		s := unsafe.Slice(elms, oidSet.oidSet.count)
		assert.Equal(2, len(s))
		for i, cOid := range s {
			oid := oidFromGssOid(&cOid)
			oidString, err := oid2String(oid)
			assert.NoErrorFatal(err)
			assert.Equal(mechs[i].OidString(), oidString)
		}
	}
}
