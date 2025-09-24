// SPDX-License-Identifier: Apache-2.0

package gssapi

import (
	"testing"

	g "github.com/golang-auth/go-gssapi/v3"
)

func TestHasExtension(t *testing.T) {
	assert := NewAssert(t)

	assert.True(ta.lib.HasExtension(g.HasExtChannelBindingSignalling))
	assert.True(ta.lib.HasExtension(g.HasExtLocalname))
	assert.False(ta.lib.HasExtension(-1))
}
