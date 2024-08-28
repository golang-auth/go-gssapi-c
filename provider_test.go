package gssapi

import (
	"testing"

	g "github.com/golang-auth/go-gssapi/v3"
	"github.com/stretchr/testify/assert"
)

func TestProvider(t *testing.T) {
	p := g.NewProvider("GSSAPI-C")
	assert.IsType(t, &provider{}, p)
}
