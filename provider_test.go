// SPDX-License-Identifier: Apache-2.0

package gssapi

import (
	"testing"

	g "github.com/golang-auth/go-gssapi/v3"
	"github.com/stretchr/testify/assert"
)

func TestProvider(t *testing.T) {
	p, err := g.NewProvider("github.com/golang-auth/go-gssapi-c")
	assert.NoError(t, err)
	assert.IsType(t, &provider{}, p)
}
