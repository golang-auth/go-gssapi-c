// SPDX-License-Identifier: Apache-2.0

package gssapi

import (
	"errors"
	"fmt"
	"testing"
	"time"

	g "github.com/golang-auth/go-gssapi/v3"
)

func TestImportName(t *testing.T) {
	assert := NewAssert(t)

	// two good names..
	name, err := ta.lib.ImportName("fooname", g.GSS_NT_USER_NAME)
	assert.NoError(err)
	defer releaseName(name)

	name, err = ta.lib.ImportName("fooname", g.GSS_NT_HOSTBASED_SERVICE)
	assert.NoError(err)
	defer releaseName(name)

	// and a "bad" name
	_, err = ta.lib.ImportName("bar", g.GSS_NT_EXPORT_NAME)
	// Heimdal and MIT differ in their opinion of the real error..
	assert.True(errors.Is(err, g.ErrBadName) || errors.Is(err, g.ErrDefectiveToken))
}

func TestInquireNamesForMech(t *testing.T) {
	assert := NewAssert(t)

	nameTypes, err := ta.lib.InquireNamesForMech(g.GSS_MECH_KRB5)
	assert.NoErrorFatal(err)
	assert.Contains(nameTypes, g.GSS_KRB5_NT_PRINCIPAL_NAME)
	assert.Contains(nameTypes, g.GSS_NT_USER_NAME)
	assert.Contains(nameTypes, g.GSS_NT_HOSTBASED_SERVICE)
}

func TestCompareName(t *testing.T) {
	// gss_compare_name seems broken in Heimdal versions 1.6 and below
	if isHeimdal() && isHeimdalBefore7() {
		t.Skip("skipping test in this old version of Heimdal")
	}
	assert := NewAssert(t)

	var tests = []struct {
		testName  string
		princName string
		nameType  g.GssNameType
		isEqual   bool
	}{
		{"same name", "fooname", g.GSS_NT_USER_NAME, true},
		{"different name", "barname", g.GSS_NT_USER_NAME, false},
		{"different type", "fooname", g.GSS_NT_HOSTBASED_SERVICE, false},
	}

	name1, err := ta.lib.ImportName("fooname", g.GSS_NT_USER_NAME)
	assert.NoErrorFatal(err)
	defer releaseName(name1)

	for _, tt := range tests {
		t.Run(tt.testName, func(t *testing.T) {
			assert := NewAssert(t)
			thisName, err := ta.lib.ImportName(tt.princName, tt.nameType)
			assert.NoErrorFatal(err)
			defer releaseName(thisName)

			equal, err := name1.Compare(thisName)
			assert.NoError(err)

			if tt.isEqual {
				assert.True(equal)
			} else {
				assert.False(equal)
			}
		})
	}

}

func TestDisplayName(t *testing.T) {
	assert := NewAssert(t)

	name1, err := ta.lib.ImportName("fooname", g.GSS_NT_USER_NAME)
	assert.NoErrorFatal(err)
	defer releaseName(name1)

	displayName, nameType, err := name1.Display()
	assert.NoError(err)
	assert.Equal("fooname", displayName)
	assert.Equal(g.GSS_NT_USER_NAME, nameType)

	// The value passed to gss_display_name will be null..
	name2 := GssName{}
	_, _, err = name2.Display()

	// Heimdal doesn't return the Calling Errors defined in RFC 2744 § 3.9.1
	if !isHeimdal() {
		assert.ErrorIs(err, ErrInaccessibleRead)
	}
	assert.ErrorIs(err, g.ErrBadName)
}

func TestInquireMechsForName(t *testing.T) {

	type testInfo struct {
		name            string
		nameType        g.GssNameType
		expectError     bool
		expectMechCount int
	}

	var tests []testInfo

	switch {
	default:
		tests = []testInfo{
			{"", g.GSS_NT_ANONYMOUS, false, 0},
			{"foo", g.GSS_NT_HOSTBASED_SERVICE, false, 3},
			{"foo@bar.com", g.GSS_KRB5_NT_ENTERPRISE_NAME, false, 0},
			{"foo@bar.com", g.GSS_KRB5_NT_PRINCIPAL_NAME, false, 2},
		}

	case isMacGssapi():
		tests = []testInfo{
			{"", g.GSS_NT_ANONYMOUS, false, 0},
			{"foo", g.GSS_NT_HOSTBASED_SERVICE, false, 3},
			{"foo@bar.com", g.GSS_KRB5_NT_PRINCIPAL_NAME, false, 2},
		}

	case isHeimdalBefore7():
		tests = []testInfo{
			{"foo", g.GSS_NT_HOSTBASED_SERVICE, false, 2},
			{"foo@bar.com", g.GSS_KRB5_NT_PRINCIPAL_NAME, false, 2},
		}

	case isHeimdal():
		tests = []testInfo{
			{"foo", g.GSS_NT_HOSTBASED_SERVICE, false, 2},
			{"foo@bar.com", g.GSS_KRB5_NT_PRINCIPAL_NAME, false, 1},
		}
	}

	for _, tt := range tests {
		name := fmt.Sprintf("%s:%s", tt.nameType.String(), tt.name)
		t.Run(name, func(t *testing.T) {
			assert := NewAssert(t)

			gssName, err := ta.lib.ImportName(tt.name, tt.nameType)
			assert.NoErrorFatal(err)
			defer releaseName(gssName)

			mechs, err := gssName.InquireMechs()
			assert.Equal(tt.expectError, err != nil)
			if !tt.expectError {
				assert.Equal(tt.expectMechCount, len(mechs))
			}
		})
	}

}

func TestCanonicalizeName(t *testing.T) {
	assert := NewAssert(t)

	name1, err := ta.lib.ImportName("foo", g.GSS_NT_USER_NAME)
	assert.NoErrorFatal(err)
	defer releaseName(name1)

	// test with a config that allows the Kerberos to find the realm
	ta.useAsset(t, testCfg1)
	time.Sleep(1 * time.Millisecond) // Why on earth is this necessary??

	cName1, err := name1.Canonicalize(g.GSS_MECH_KRB5)
	assert.NoError(err)
	defer releaseName(cName1)

	// test with a config that has no default realm, so this should fail to canonicalize
	// on MIT (but NOT on Heimdal which uses krb5_get_host_realm(local hostname) to find
	// a default realm)
	if !isHeimdal() {
		ta.useAsset(t, testCfg2)
		time.Sleep(1 * time.Millisecond) // Why on earth is this necessary??
		_, err = name1.Canonicalize(g.GSS_MECH_KRB5)

		assert.Error(err)
		if err != nil {
			assert.Contains(err.Error(), "does not specify default realm")
		}
	} else {
		t.Log("skipping canonicalize with no default realm on recent Heimdal")
	}
}

func TestExportName(t *testing.T) {
	assert := NewAssert(t)

	ta.useAsset(t, testCfg1)

	name1, err := ta.lib.ImportName("fooname", g.GSS_NT_USER_NAME)
	assert.NoErrorFatal(err)
	defer name1.Release() //nolint:errcheck

	// should error as name1 was not generated by gss_accept_sec_context or gss_canonicalize_name
	// (except for Heimdal - why?..)
	if !isHeimdal() {
		_, err = name1.Export()
		assert.ErrorIs(err, g.ErrNameNotMn)
	}

	// now canonicalize amd try again
	cName1, err := name1.Canonicalize(g.GSS_MECH_KRB5)
	assert.NoErrorFatal(err)
	exp, err := cName1.Export()
	assert.NoError(err)
	if err != nil {
		assert.NotEmpty(exp)
	}
}

func TestDuplicateName(t *testing.T) {
	assert := NewAssert(t)

	name1, err := ta.lib.ImportName("fooname", g.GSS_NT_USER_NAME)
	assert.NoErrorFatal(err)
	defer name1.Release() //nolint:errcheck

	name2, err := name1.Duplicate()
	assert.NoErrorFatal(err)
	defer name2.Release() //nolint:errcheck

	equal, err := name1.Compare(name2)
	assert.NoError(err)
	assert.True(equal)

	equal, err = name2.Compare(name1)
	assert.NoError(err)
	assert.True(equal)

}
