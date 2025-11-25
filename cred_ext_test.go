// SPDX-License-Identifier: Apache-2.0

package gssapi

import (
	"testing"

	g "github.com/golang-auth/go-gssapi/v3"
)

func TestNewCredStore(t *testing.T) {
	assert := NewAssert(t)

	store := newCredStore()
	assert.NotNil(store)
	assert.Equal(0, len(store))
}

func TestCredStoreSetOption(t *testing.T) {
	assert := NewAssert(t)

	store := newCredStore()

	// Test setting a single option
	err := store.SetOption(int(g.CredStoreCCache), "FILE:/tmp/test")
	assert.NoError(err)
	assert.Equal(1, len(store))

	// Test setting multiple options
	err = store.SetOption(int(g.CredStoreClientKeytab), "FILE:/tmp/keytab")
	assert.NoError(err)
	assert.Equal(2, len(store))

	err = store.SetOption(int(g.CredStorePassword), "secret")
	assert.NoError(err)
	assert.Equal(3, len(store))

	// Test overwriting an existing option
	err = store.SetOption(int(g.CredStoreCCache), "FILE:/tmp/other")
	assert.NoError(err)
	assert.Equal(3, len(store))
}

func TestCredStoreGetOption(t *testing.T) {
	assert := NewAssert(t)

	store := newCredStore()

	// Test getting a non-existent option
	value, ok := store.GetOption(int(g.CredStoreCCache))
	assert.False(ok)
	assert.Empty(value)

	// Set an option and retrieve it
	expectedValue := "FILE:/tmp/test"
	err := store.SetOption(int(g.CredStoreCCache), expectedValue)
	assert.NoError(err)

	value, ok = store.GetOption(int(g.CredStoreCCache))
	assert.True(ok)
	assert.Equal(expectedValue, value)

	// Test getting a different option that doesn't exist
	value, ok = store.GetOption(int(g.CredStoreServerKeytab))
	assert.False(ok)
	assert.Empty(value)
}

func TestCredStoreGetSetAllOptions(t *testing.T) {
	assert := NewAssert(t)

	store := newCredStore()

	tests := []struct {
		option int
		value  string
	}{
		{int(g.CredStoreCCache), "FILE:/tmp/ccache"},
		{int(g.CredStoreClientKeytab), "FILE:/tmp/client.keytab"},
		{int(g.CredStoreServerKeytab), "FILE:/tmp/server.keytab"},
		{int(g.CredStorePassword), "mypassword"},
		{int(g.CredStoreRCache), "FILE:/tmp/rcache"},
		{int(g.CredStoreVerify), "host/test.example.com"},
	}

	// Set all options
	for _, tt := range tests {
		err := store.SetOption(tt.option, tt.value)
		assert.NoError(err, "Failed to set option %d", tt.option)
	}

	assert.Equal(len(tests), len(store))

	// Retrieve all options
	for _, tt := range tests {
		value, ok := store.GetOption(tt.option)
		assert.True(ok, "Option %d should exist", tt.option)
		assert.Equal(tt.value, value, "Option %d should have correct value", tt.option)
	}
}

func TestCredStoreKvEmpty(t *testing.T) {
	assert := NewAssert(t)

	store := newCredStore()

	kv := store.kv()
	assert.NotNil(kv.kvset)
	assert.Equal(0, int(kv.kvset.count))

	kv.Release()
}

func TestCredStoreKvSingleOption(t *testing.T) {
	assert := NewAssert(t)

	store := newCredStore()
	err := store.SetOption(int(g.CredStoreCCache), "FILE:/tmp/test")
	assert.NoError(err)

	kv := store.kv()
	defer kv.Release()

	assert.NotNil(kv.kvset)
	assert.Equal(1, int(kv.kvset.count))
	assert.NotNil(kv.kvset.elements)

	key, value := kv.kv(0)
	assert.Equal("ccache", key)
	assert.Equal("FILE:/tmp/test", value)
}

func TestCredStoreKvOptionKeyMappings(t *testing.T) {
	tests := []struct {
		name        string
		option      int
		value       string
		expectedKey string
	}{
		{"CCache", int(g.CredStoreCCache), "FILE:/tmp/ccache", "ccache"},
		{"ClientKeytab", int(g.CredStoreClientKeytab), "FILE:/tmp/client.keytab", "client_keytab"},
		{"ServerKeytab", int(g.CredStoreServerKeytab), "FILE:/tmp/server.keytab", "keytab"},
		{"Password", int(g.CredStorePassword), "mypassword", "password"},
		{"RCache", int(g.CredStoreRCache), "FILE:/tmp/rcache", "rcache"},
		{"Verify", int(g.CredStoreVerify), "host/test.example.com", "verify"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := NewAssert(t)
			store := newCredStore()
			err := store.SetOption(tt.option, tt.value)
			assert.NoError(err)

			kvset := store.kv()
			defer kvset.Release()

			assert.NotNil(kvset.kvset)
			assert.Equal(1, int(kvset.kvset.count))
			assert.NotNil(kvset.kvset.elements)

			kv := kvset.Get(0)
			assert.NotNil(kv.key)
			assert.NotNil(kv.value)

			key, value := kvset.kv(0)
			assert.Equal(tt.expectedKey, key)
			assert.Equal(tt.value, value)
		})
	}
}

func TestCredStoreKvAllOptions(t *testing.T) {
	assert := NewAssert(t)

	store := newCredStore()
	testValues := map[int]string{
		int(g.CredStoreCCache):       "FILE:/tmp/ccache",
		int(g.CredStoreClientKeytab): "FILE:/tmp/client.keytab",
		int(g.CredStoreServerKeytab): "FILE:/tmp/server.keytab",
		int(g.CredStorePassword):     "mypassword",
		int(g.CredStoreRCache):       "FILE:/tmp/rcache",
		int(g.CredStoreVerify):       "host/test.example.com",
	}

	// Set all options
	for opt, value := range testValues {
		err := store.SetOption(opt, value)
		assert.NoError(err)
	}

	kvset := store.kv()
	defer kvset.Release()

	assert.NotNil(kvset.kvset)
	assert.Equal(len(testValues), int(kvset.kvset.count))
	assert.NotNil(kvset.kvset.elements)
}

func TestCredStoreKv(t *testing.T) {
	assert := NewAssert(t)

	store := newCredStore()
	err := store.SetOption(int(g.CredStoreServerKeytab), "FILE:/tmp/keytab")
	assert.NoError(err)

	// Pass nil pinner - should create a new one
	kvset := store.kv()
	defer kvset.Release()

	assert.NotNil(kvset.kvset)
	assert.Equal(1, int(kvset.kvset.count))
}

func TestCredStoreKvUnknownOption(t *testing.T) {
	assert := NewAssert(t)

	store := newCredStore()
	// Set an option that's not in the switch statement
	err := store.SetOption(999, "unknown value")
	assert.NoError(err)

	kvset := store.kv()
	defer kvset.Release()

	assert.NotNil(kvset.kvset)
	assert.Equal(0, int(kvset.kvset.count))
	assert.Nil(kvset.kvset.elements)

	kv := kvset.Get(0)
	assert.Nil(kv)

	key, value := kvset.kv(0)
	assert.Equal("", key)
	assert.Equal("", value)
}

func TestCredStoreSetOptionEmptyValue(t *testing.T) {
	assert := NewAssert(t)

	store := newCredStore()

	// Test setting an empty value
	err := store.SetOption(int(g.CredStoreVerify), "")
	assert.NoError(err)

	value, ok := store.GetOption(int(g.CredStoreVerify))
	assert.True(ok)
	assert.Empty(value)
}

func TestCredStoreMultipleOptionsSameValue(t *testing.T) {
	assert := NewAssert(t)

	store := newCredStore()
	value := "FILE:/tmp/shared"

	err := store.SetOption(int(g.CredStoreCCache), value)
	assert.NoError(err)

	err = store.SetOption(int(g.CredStoreServerKeytab), value)
	assert.NoError(err)

	assert.Equal(2, len(store))

	// Both should return the same value
	ccacheValue, ok := store.GetOption(int(g.CredStoreCCache))
	assert.True(ok)
	assert.Equal(value, ccacheValue)

	keytabValue, ok := store.GetOption(int(g.CredStoreServerKeytab))
	assert.True(ok)
	assert.Equal(value, keytabValue)
}

func TestAcquireCredentialFrom(t *testing.T) {
	if !ta.lib.HasExtension(g.HasExtCredStore) {
		t.Log("skipping acquire credential from test because provider does not support the CredStore extension")
		t.SkipNow()
	}

	assert := NewAssert(t)

	var err error
	mechs := []g.GssMech{g.GSS_MECH_KRB5}

	p := ta.lib.(g.ProviderExtCredStore)

	// Try to acquire creds for initiate and accept when we only have a valid
	// keytab -- only 'accept' should work
	opts := []g.CredStoreOption{
		g.WithCredStoreCCache("FILE:/no/such/file"),
		g.WithCredStoreServerKeytab("FILE:" + ta.ktfileRack),
	}

	_, err = p.AcquireCredentialFrom(nil, mechs, g.CredUsageAcceptOnly, nil, opts...)
	assert.NoError(err)
	_, err = p.AcquireCredentialFrom(nil, mechs, g.CredUsageInitiateOnly, nil, opts...)
	assert.Error(err)
	_, err = p.AcquireCredentialFrom(nil, mechs, g.CredUsageInitiateAndAccept, nil, opts...)
	assert.Error(err)

	// Try again but only with a credentials cache -- only initiate should work
	opts = []g.CredStoreOption{
		g.WithCredStoreCCache("FILE:" + ta.ccfile),
		g.WithCredStoreServerKeytab("FILE:/no/such/file"),
	}

	_, err = p.AcquireCredentialFrom(nil, mechs, g.CredUsageAcceptOnly, nil, opts...)
	assert.Error(err)
	_, err = p.AcquireCredentialFrom(nil, mechs, g.CredUsageInitiateOnly, nil, opts...)
	assert.NoError(err)
	_, err = p.AcquireCredentialFrom(nil, mechs, g.CredUsageInitiateAndAccept, nil, opts...)
	assert.Error(err)

	// Try again with KR and ccache -- all should work
	opts = []g.CredStoreOption{
		g.WithCredStoreCCache("FILE:" + ta.ccfile),
		g.WithCredStoreServerKeytab("FILE:" + ta.ktfileRack),
	}

	_, err = p.AcquireCredentialFrom(nil, mechs, g.CredUsageAcceptOnly, nil, opts...)
	assert.NoError(err)
	_, err = p.AcquireCredentialFrom(nil, mechs, g.CredUsageInitiateOnly, nil, opts...)
	assert.NoError(err)
	_, err = p.AcquireCredentialFrom(nil, mechs, g.CredUsageInitiateAndAccept, nil, opts...)
	assert.NoError(err)
}

func TestStoreInfo(t *testing.T) {
	if !ta.lib.HasExtension(g.HasExtCredStore) {
		t.Log("skipping store info test because provider does not support the CredStore extension")
		t.SkipNow()
	}

	assert := NewAssert(t)

	// Grab the default cred from the default cache
	ta.useAsset(t, testNoKeytab|testCredCache)

	cred, err := ta.lib.AcquireCredential(nil, nil, g.CredUsageInitiateOnly, nil)
	assert.NoErrorFatal(err)

	credExt := cred.(g.CredentialExtCredStore)

	tmpStore := ta.tmpFilename()

	// Store it back into a different cache
	opts := []g.CredStoreOption{
		g.WithCredStoreCCache("FILE:" + tmpStore),
	}

	mechsStored, usageStored, err := credExt.StoreInto(nil, g.CredUsageInitiateOnly, true, true, opts...)
	assert.NoError(err)
	assert.Equal(1, len(mechsStored))
	assert.Equal(g.CredUsageInitiateOnly, usageStored)

	// Verify the credential was stored
	assert.FileExists(tmpStore)
}

func TestAddCredentialFrom(t *testing.T) {
	if !ta.lib.HasExtension(g.HasExtCredStore) {
		t.Log("skipping store info test because provider does not support the CredStore extension")
		t.SkipNow()
	}

	// TOODO: its not clear how to test this
}
