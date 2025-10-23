package gssapi

import (
	"testing"
	"unsafe"

	g "github.com/golang-auth/go-gssapi/v3"
)

func TestGssOidSetFromOids(t *testing.T) {
	assert := NewAssert(t)

	oids := []g.Oid{}

	// test with no OIDs
	oidSet, pinner := gssOidSetFromOids(oids, nil)
	assert.NotNil(pinner)
	if pinner != nil {
		pinner.Unpin()
	}
	assert.Nil(oidSet)

	mechs := []g.GssMech{g.GSS_MECH_KRB5, g.GSS_MECH_IAKERB}

	// Test with some OIDs
	oids = append(oids, mechs[0].Oid(), mechs[1].Oid())
	oidSet, pinner = gssOidSetFromOids(oids, nil)
	assert.NotNil(oidSet)
	assert.NotNil(pinner)

	if oidSet != nil {
		assert.Equal(2, int(oidSet.count))

		elms := oidSet.elements
		s := unsafe.Slice(elms, oidSet.count)
		for i, cOid := range s {
			oid := oidFromGssOid(&cOid)
			oidString, err := oid2String(oid)
			assert.NoErrorFatal(err)
			assert.Equal(mechs[i].OidString(), oidString)
		}
	}
	if pinner != nil {
		pinner.Unpin()
	}
}

func TestOid2String(t *testing.T) {
	assert := NewAssert(t)

	oid := g.GSS_MECH_KRB5.Oid()
	oidString, err := oid2String(oid)
	assert.NoError(err)
	assert.Equal(g.GSS_MECH_KRB5.OidString(), oidString)
}
