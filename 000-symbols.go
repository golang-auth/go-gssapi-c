// SPDX-License-Identifier: Apache-2.0

package gssapi

import (
	"unsafe"
)

/*
#include <dlfcn.h>
#include <stdint.h>
*/
import "C"

// Maps symbols that we look for in the binary to their addresses
var optionalSymbols = make(map[string]unsafe.Pointer)

func init() {
	// Look for these symbols in the binary
	syms := []string{
		"gss_localname",
		"gss_duplicate_cred", // Signals rewrite of gss_add_cred
		"gss_unwrap_aead",    // Appeared in Heimdal 7.0.1
		"krb5_gss_register_acceptor_identity",
		"gsskrb5_register_acceptor_identity",
		"gss_krb5_ccache_name",
		"gsskrb5_set_default_realm",
		"krb5_is_thread_safe",
		"gss_display_name",
		"gss_inquire_name",
	}

	cDlHandle := C.dlopen(nil, C.RTLD_NOW)
	if cDlHandle == nil {
		panic("faied to open library")
	}

	defer C.dlclose(cDlHandle)

	for _, sym := range syms {
		ptr := C.dlsym(cDlHandle, C.CString(sym))
		optionalSymbols[sym] = ptr
	}
}

func hasSymbol(sym string) bool {
	return optionalSymbols[sym] != nil
}

func librarySymbol(sym string) unsafe.Pointer {
	return optionalSymbols[sym]
}

// Maps a library symbol name to a C function pointer that will be used to call the symbol
type symbolMap map[string]**[0]byte

// Set the C function pointer for each symbol in the map, to the location in memory of the symbol
func (m *symbolMap) Apply() {
	for sym, ptr := range *m {
		funcPtr := librarySymbol(sym)
		if funcPtr != nil {
			*ptr = (*[0]byte)(funcPtr)
		}
	}
}
