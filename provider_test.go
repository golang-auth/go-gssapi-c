// SPDX-License-Identifier: Apache-2.0

package gssapi

import (
	"runtime"
	"testing"

	g "github.com/golang-auth/go-gssapi/v3"
	"github.com/stretchr/testify/assert"
)

func TestProvider(t *testing.T) {
	p, err := g.NewProvider("github.com/golang-auth/go-gssapi-c")
	assert.NoError(t, err)
	assert.IsType(t, &provider{}, p)
}

func TestNew(t *testing.T) {
	p, err := New()
	assert.NoError(t, err)
	assert.NotNil(t, p)
	assert.IsType(t, &provider{}, p)
}

func TestProvider_Name(t *testing.T) {
	p, err := New()
	assert.NoError(t, err)

	name := p.Name()
	assert.Equal(t, LIBID, name)
}

func TestProvider_HasExtension(t *testing.T) {
	p, err := New()
	assert.NoError(t, err)

	// Test all known extension types
	tests := []struct {
		name     string
		ext      g.GssapiExtension
		expected bool // We can't predict the actual value, but we can verify it doesn't panic
	}{
		{
			name:     "HasExtChannelBindingSignalling",
			ext:      g.HasExtChannelBindingSignalling,
			expected: hasChannelBound(),
		},
		{
			name:     "HasExtLocalname",
			ext:      g.HasExtLocalname,
			expected: hasSymbol("gss_localname"),
		},
		{
			name:     "HasExtKrb5Identity",
			ext:      g.HasExtKrb5Identity,
			expected: false,
		},
		{
			name:     "HasExtRFC4178",
			ext:      g.HasExtRFC4178,
			expected: false, // Not implemented in this provider
		},
		{
			name:     "HasExtRFC5588",
			ext:      g.HasExtRFC5588,
			expected: false, // Not implemented in this provider
		},
		{
			name:     "HasExtRFC6680",
			ext:      g.HasExtRFC6680,
			expected: false, // Not implemented in this provider
		},
		{
			name:     "HasExtRFC5587",
			ext:      g.HasExtRFC5587,
			expected: false, // Not implemented in this provider
		},
		{
			name:     "HasExtRFC5801",
			ext:      g.HasExtRFC5801,
			expected: false, // Not implemented in this provider
		},
		{
			name:     "HasExtRFC4121",
			ext:      g.HasExtRFC4121,
			expected: false, // Not implemented in this provider
		},
		{
			name:     "HasExtGGF",
			ext:      g.HasExtGGF,
			expected: false, // Not implemented in this provider
		},
		{
			name:     "HasExtS4U",
			ext:      g.HasExtS4U,
			expected: false, // Not implemented in this provider
		},
		{
			name:     "HasExtCredPassword",
			ext:      g.HasExtCredPassword,
			expected: false, // Not implemented in this provider
		},
		{
			name:     "Unknown extension",
			ext:      g.GssapiExtension(999), // Invalid/unknown extension
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := p.HasExtension(tt.ext)
			assert.Equal(t, tt.expected, result, "HasExtension(%v) should return %v", tt.ext, tt.expected)
		})
	}
}

func TestErrTooLarge(t *testing.T) {
	// Verify the error variable exists and has the expected message
	assert.NotNil(t, ErrTooLarge)
	assert.Equal(t, "the GSSAPI-C bindings only support up to 32 bit messages", ErrTooLarge.Error())
}

func TestIsHeimdal(t *testing.T) {
	// This function calls C code, so we can't easily mock it
	// But we can at least verify it doesn't panic and returns a boolean
	result := isHeimdal()
	assert.IsType(t, false, result)
}

func TestIsHeimdalBefore7(t *testing.T) {
	// This depends on isHeimdal() and hasSymbol()
	result := isHeimdalBefore7()
	assert.IsType(t, false, result)

	// If Heimdal is detected, before7 and after7 should be mutually exclusive
	if isHeimdal() {
		before7 := isHeimdalBefore7()
		after7 := isHeimdalAfter7()
		assert.NotEqual(t, before7, after7, "isHeimdalBefore7 and isHeimdalAfter7 should be mutually exclusive when Heimdal is detected")
	}
}

func TestIsHeimdalAfter7(t *testing.T) {
	// This depends on isHeimdal() and hasSymbol()
	result := isHeimdalAfter7()
	assert.IsType(t, false, result)

	// If Heimdal is detected, before7 and after7 should be mutually exclusive
	if isHeimdal() {
		before7 := isHeimdalBefore7()
		after7 := isHeimdalAfter7()
		assert.NotEqual(t, before7, after7, "isHeimdalBefore7 and isHeimdalAfter7 should be mutually exclusive when Heimdal is detected")
	}
}

func TestIsHeimdalWorkingAddCred(t *testing.T) {
	// This depends on isHeimdal() and hasSymbol()
	result := isHeimdalWorkingAddCred()
	assert.IsType(t, false, result)

	// If not Heimdal, this should always be false
	if !isHeimdal() {
		assert.False(t, result, "isHeimdalWorkingAddCred should be false when not Heimdal")
	}
}

func TestHasChannelBound(t *testing.T) {
	// This function calls C code, so we can't easily mock it
	// But we can at least verify it doesn't panic and returns a boolean
	result := hasChannelBound()
	assert.IsType(t, false, result)
}

func TestIsMacGssapi(t *testing.T) {
	// This function calls C code, so we can't easily mock it
	// But we can at least verify it doesn't panic and returns a boolean
	result := isMacGssapi()
	assert.IsType(t, false, result)
}

func TestIsHeimdalFreeBSD(t *testing.T) {
	result := isHeimdalFreeBSD()
	assert.IsType(t, false, result)

	// If not FreeBSD, this should always be false
	if runtime.GOOS != "freebsd" {
		assert.False(t, result, "isHeimdalFreeBSD should be false when not on FreeBSD")
	}

}
