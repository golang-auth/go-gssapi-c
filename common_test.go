package gssapi

import (
	"encoding/base64"
	"io"
	"os"
	"strings"
	"testing"

	g "github.com/golang-auth/go-gssapi/v3"
	"github.com/stretchr/testify/assert"
)

//go:generate  build-tools/mk-test-vectors -o testvecs_test.go

func TestMain(m *testing.M) {
	ta = mkTestAssets()
	defer ta.Free()

	m.Run()
}

// Local version of testify/assert  with some extensions
type myassert struct {
	*assert.Assertions

	t *testing.T
}

// Fail the test immediately on error
func (a *myassert) NoErrorFatal(err error) {
	a.Assertions.NoError(err)
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

type saveVars struct {
	vars map[string]string
}

func newSaveVars(varNames ...string) saveVars {
	sv := saveVars{
		vars: make(map[string]string),
	}

	for _, varName := range varNames {
		sv.vars[varName] = os.Getenv(varName)
	}

	return sv
}

func (sv saveVars) Restore() {
	for varName, varVal := range sv.vars {
		if varVal == "" {
			os.Unsetenv(varName)
		} else {
			os.Setenv(varName, varVal)
		}
	}
}

type testAssets struct {
	ktfileRack string
	ktfileRuin string
	ccfile     string
	cfgfile1   string
	cfgfile2   string
	lib        g.Provider

	saveVars saveVars
}

func mkTestAssets() *testAssets {
	ta := &testAssets{
		saveVars: newSaveVars("KRB5_KTNAME", "KRB5CCNAME", "KRB5_CONFIG"),
		lib:      New(),
	}

	ktName1, krName2, ccName, err := writeKrbCreds()
	if err != nil {
		panic(err)
	}

	ta.ktfileRack = ktName1
	ta.ktfileRuin = krName2
	ta.ccfile = ccName

	cfName1, cfName2, err := writeKrb5Confs()
	if err != nil {
		panic(err)
	}

	ta.cfgfile1 = cfName1
	ta.cfgfile2 = cfName2

	return ta
}

func (ta *testAssets) Free() {
	ta.saveVars.Restore()
	os.Remove(ta.ktfileRack)
	os.Remove(ta.ktfileRuin)
	os.Remove(ta.ccfile)
}

type testAssetType int

const (
	testKeytabRack testAssetType = 1 << iota
	testKeytabRuin
	testCredCache
	testNoCredCache
	testNoKeytab
	testCfg1
	testCfg2
	testNoCfg
)

func (ta *testAssets) useAsset(at testAssetType) {
	switch {
	default:
		os.Unsetenv("KRB5_KTNAME")
	case at&testKeytabRack > 0:
		os.Setenv("KRB5_KTNAME", ta.ktfileRack)
	case at&testKeytabRuin > 0:
		os.Setenv("KRB5_KTNAME", ta.ktfileRuin)
	case at&testNoKeytab > 0:
		os.Setenv("KRB5_KTNAME", "/no/such/file")
	}

	switch {
	default:
		os.Unsetenv("KRB5CCNAME")
	case at&testCredCache > 0:
		os.Setenv("KRB5CCNAME", "FILE:"+ta.ccfile)
	case at&testNoCredCache > 0:
		os.Setenv("KRB5CCNAME", "FILE:/no/such/file")
	}

	switch {
	default:
		os.Unsetenv("KRB5_CONFIG")
	case at&testCfg1 > 0:
		os.Setenv("KRB5_CONFIG", ta.cfgfile1)
	case at&testCfg2 > 0:
		os.Setenv("KRB5_CONFIG", ta.cfgfile2)
	case at&testNoCfg > 0:
		os.Setenv("KRB5_CONFIG", "/no/such/file")
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

	fn := fh.Name()
	_, err = io.Copy(fh, r)
	fh.Close()

	return fn, err
}

func writeKrbCreds() (kt1, kt2, cc string, err error) {
	kt1, err = writeTmpBase64(ktdata1)
	if err != nil {
		return
	}
	kt2, err = writeTmpBase64(ktdata2)
	if err != nil {
		return
	}

	cc, err = writeTmpBase64(ccdata)

	return
}

// default realm defined
var krb5Conf1 = `
[libdefaults]

dns_lookup_realm = false
default_realm = FOO.COM
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
	fh.Close()

	fh, err = os.CreateTemp("", "test")
	if err != nil {
		return
	}

	f2 = fh.Name()
	if _, err = io.WriteString(fh, krb5Conf2); err != nil {
		return
	}
	fh.Close()

	return
}
