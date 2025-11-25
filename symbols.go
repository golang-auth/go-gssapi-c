// SPDX-License-Identifier: Apache-2.0

package gssapi

import (
	"sync"
	"unsafe"
)

/*
#include <dlfcn.h>
#include <stdint.h>
*/
import "C"

// Maps symbols that we look for in the binary to their addresses
var optionalSymbols = make(map[string]unsafe.Pointer)

// This runs once via sync.Once
func readSymbols() {
	// Look for these symbols in the binary
	syms := []string{
		"gss_localname",
		"gss_duplicate_cred", // Signals rewrite of gss_add_cred
		"gss_unwrap_aead",    // Appeared in Heimdal 7.0.1
		"krb5_is_thread_safe",
		"gss_display_name",
		"gss_inquire_name",
		"gss_acquire_cred_from", // Credential Store extension
		"gss_store_cred_into",   // Credential Store extension
		"gss_add_cred_from",     // Credential Store extension
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

var onceSymbols = sync.Once{}

func hasSymbol(sym string) bool {
	onceSymbols.Do(readSymbols)
	return optionalSymbols[sym] != nil
}

func librarySymbol(sym string) unsafe.Pointer {
	onceSymbols.Do(readSymbols)
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
