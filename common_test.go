// SPDX-License-Identifier: Apache-2.0

package gssapi

import (
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	g "github.com/golang-auth/go-gssapi/v3"
	"github.com/stretchr/testify/assert"
)

//go:generate  build-tools/mk-test-vectors -o testvecs_test.go

func init() {
	// RC4 woes
	if isHeimdalFreeBSD() {
		_ = os.Setenv("OPENSSL_CONF", "./openssl.cnf")
	}
}

func TestMain(m *testing.M) {
	ta = mkTestAssets()
	defer ta.Free()

	fmt.Fprintf(os.Stderr, "isHeimdal: %v\n", isHeimdal())

	ta.useAsset(nil, testCfg1)

	m.Run()
}

// Local version of testify/assert  with some extensions
type myassert struct {
	*assert.Assertions

	t *testing.T
}

// Fail the test immediately on error
func (a *myassert) NoErrorFatal(err error) {
	a.NoError(err)
	if err != nil {
		a.t.Logf("Stopping test %s due to fatal error", a.t.Name())
		a.t.FailNow()
	}
}

func NewAssert(t *testing.T) *myassert {
	a := assert.New(t)
	return &myassert{a, t}
}

func releaseName(name g.GssName) {
	if name != nil {
		_ = name.Release()
	}
}

type testAssets struct {
	ktName     string
	ktfileRack string
	ktfileRuin string
	ktfileAll  string
	ccName     string
	ccfile     string
	cfgfile1   string
	cfgfile2   string
	lib        g.Provider
}

func mkTestAssets() *testAssets {
	p, err := New()
	if err != nil {
		panic(err)
	}
	ta := &testAssets{
		lib: p,
	}

	ktName, ktName1, krName2, ktNameAll, ccName, cc1, err := writeKrbCreds()
	if err != nil {
		panic(err)
	}

	ta.ktName = ktName
	ta.ktfileRack = ktName1
	ta.ktfileRuin = krName2
	ta.ktfileAll = ktNameAll
	ta.ccfile = cc1
	ta.ccName = ccName

	cfName1, cfName2, err := writeKrb5Confs()
	if err != nil {
		panic(err)
	}

	ta.cfgfile1 = cfName1
	ta.cfgfile2 = cfName2

	_ = os.Setenv("KRB5CCNAME", "FILE:"+ta.ccName)
	_ = os.Setenv("KRB5_KTNAME", "FILE:"+ta.ktName)

	return ta
}

func (ta *testAssets) Free() {
	_ = os.Remove(ta.ktName)
	_ = os.Remove(ta.cfgfile1)
	_ = os.Remove(ta.cfgfile2)
	_ = os.Remove(ta.ktfileRack)
	_ = os.Remove(ta.ktfileRuin)
	_ = os.Remove(ta.ktfileAll)
	_ = os.Remove(ta.ccfile)
	_ = os.Remove(ta.ccName)
}

type testAssetType int

const (
	testKeytabRack testAssetType = 1 << iota
	testKeytabRuin
	testKeytabAll
	testCredCache
	testNoCredCache
	testNoKeytab
	testCfg1
	testCfg2
	testNoCfg
)

func CopyFile(src, dst string) error {
	// Open the source file for reading
	sourceFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer sourceFile.Close() //nolint:errcheck

	// Create the destination file for writing, truncating if it already exists
	destinationFile, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer destinationFile.Close() //nolint:errcheck

	// Copy the contents from the source to the destination
	_, err = io.Copy(destinationFile, sourceFile)
	if err != nil {
		return fmt.Errorf("failed to copy file contents: %w", err)
	}

	err = os.Chmod(dst, 0600)
	if err != nil {
		return fmt.Errorf("failed to set destination file permissions: %w", err)
	}

	return nil
}

func (ta *testAssets) useAsset(t *testing.T, at testAssetType) {
	var err error
	switch {
	case at&testKeytabAll > 0:
		err = CopyFile(ta.ktfileAll, ta.ktName)
	case at&testKeytabRack > 0:
		err = CopyFile(ta.ktfileRack, ta.ktName)
	case at&testKeytabRuin > 0:
		err = CopyFile(ta.ktfileRuin, ta.ktName)
	case at&testNoKeytab > 0:
		err = os.Remove(ta.ktName)
	}

	if err != nil {
		if t != nil {
			t.Logf("Link keytab failed: %v", err)
		} else {
			panic(err)
		}
	}

	switch {
	case at&testCredCache > 0:
		err = CopyFile(ta.ccfile, ta.ccName)
	case at&testNoCredCache > 0:
		err = os.Remove(ta.ccName)
	}

	if err != nil {
		if t != nil {
			t.Logf("CCache link failed: %v", err)
		} else {
			panic(err)
		}
	}

	f := func(k, v string) { _ = os.Setenv(k, v) }
	if t != nil {
		f = t.Setenv
	}

	switch {
	case at&testCfg1 > 0:
		f("KRB5_CONFIG", ta.cfgfile1)
	case at&testCfg2 > 0:
		f("KRB5_CONFIG", ta.cfgfile2)
	case at&testNoCfg > 0:
		f("KRB5_CONFIG", "/no/such/file")
	}
}

var ta *testAssets

func writeTmpBase64(b64 string) (string, error) {
	r := strings.NewReader(b64)
	decoder := base64.NewDecoder(base64.StdEncoding, r)
	return writeTmp(decoder)
}

func writeTmp(r io.Reader) (string, error) {
	fh, err := os.CreateTemp("", "test")
	if err != nil {
		return "", err
	}

	defer fh.Close() //nolint:errcheck

	if err = fh.Chmod(0600); err != nil {
		return "", err
	}

	fn := fh.Name()
	_, err = io.Copy(fh, r)

	return fn, err
}

func writeKrbCreds() (ktName, kt1, kt2, ktAll, ccName, cc1 string, err error) {
	kt1, err = writeTmpBase64(ktdata1)
	if err != nil {
		return
	}
	kt2, err = writeTmpBase64(ktdata2)
	if err != nil {
		return
	}
	ktAll, err = writeTmpBase64(ktdataAll)
	if err != nil {
		return
	}

	cc1, err = writeTmpBase64(ccdata)
	if err != nil {
		return
	}

	fh, err := os.CreateTemp("", "test")
	if err != nil {
		return
	}
	ktName = fh.Name()
	fh.Close() //nolint:errcheck
	if err = os.Remove(ktName); err != nil {
		return
	}

	fh, err = os.CreateTemp("", "test")
	if err != nil {
		return
	}
	ccName = fh.Name()
	fh.Close() //nolint:errcheck
	err = os.Remove(ccName)

	return
}

// default realm defined
var krb5Conf1 = `
[libdefaults]

dns_lookup_realm = false
default_realm = GOLANG-AUTH.IO
`

// missing default realm
var krb5Conf2 = `
[libdefaults]

dns_lookup_realm = false
`

func writeKrb5Confs() (f1, f2 string, err error) {
	fh, err := os.CreateTemp("", "test")
	if err != nil {
		return
	}

	f1 = fh.Name()
	if _, err = io.WriteString(fh, krb5Conf1); err != nil {
		return
	}
	_ = fh.Close()

	fh, err = os.CreateTemp("", "test")
	if err != nil {
		return
	}

	f2 = fh.Name()
	if _, err = io.WriteString(fh, krb5Conf2); err != nil {
		return
	}
	_ = fh.Close()

	return
}
