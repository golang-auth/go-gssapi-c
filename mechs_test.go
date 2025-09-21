// SPDX-License-Identifier: Apache-2.0

package gssapi

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIndicateMechs(t *testing.T) {
	mechs, err := ta.lib.IndicateMechs()
	assert.NoError(t, err, "IndicateMechs should not return an error")
	assert.NotNil(t, mechs, "IndicateMechs should not return nil")
	assert.Greater(t, len(mechs), 0, "IndicateMechs should return at least one mechanism")

	// Check that each returned mechanism has a valid OID
	for _, mech := range mechs {
		oid := mech.Oid()
		t.Logf("Mechanism OID for %s: %s", mech.String(), mech.OidString())
		assert.NotEmpty(t, oid, "Mechanism OID for %s should not be empty", mech.String())
	}
}
