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

	// Test with one OID
	oids = append(oids, []byte{1, 2, 3, 4, 5})
	oidSet, pinner = gssOidSetFromOids(oids, nil)
	assert.NotNil(oidSet)
	assert.NotNil(pinner)
	if pinner != nil {
		pinner.Unpin()
	}
	assert.Equal(1, int(oidSet.count))

	cOid := oidSet.elements
	for i := 0; i < int(cOid.length); i++ {
		var b *byte = (*byte)(unsafe.Add(cOid.elements, i))
		t.Logf("IDX %d: %d", i, *b)
	}
}
