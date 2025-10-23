# Contribution guidelines for go-gssapi-c


## Quick Start — Welcome!

We’re glad you’re here!

Bring your ideas, code, questions, or feedback — all contributions are welcome. We value different perspectives and approaches, and believe they make the project stronger and more interesting.

Expect respectful collaboration, a focus on substance over perfection, and a willingness to learn from each other. If changes are suggested, they’re meant to help — and if you’re short on time, we can help make adjustments before merging.

Let’s build something great, together.


## Community guideliens

We believe that open source thrives on respectful collaboration and a diversity of perspectives.  This
leads to better solutions, more creativity, and a more engaging project.
We welcome and value all contributions — whether they are code, documentation, ideas, or feedback. Your time and expertise are deeply appreciated.  We don’t enforce rigid style guides or lengthy rules of conduct, but keep
some simple guidelines in mind:

 * **Be Respectful**: We ask for mutual respect and professionalism in all interactions. 
   Challenge ideas thoughtfully and be open to new viewpoints.
 * **Substance Over Perfection**: We value contributions even when they are not perfect. The project’s
   maintainers may suggest changes for clarity or consistency, but our primary focus is on the substance of your contribution.
 * **We Can Help**: If you are short on time, maintainers can assist with minor amendments to help get
   your work merged. Our goal is to create a welcoming atmosphere where contributors, including those who are less experienced, feel supported.



## Technical Guidelines
This project is a Go wrapper around a C-based GSSAPI library. Contributions should adhere to the following technical principles to maintain a clean and reliable abstraction.

### API Boundary
The public API of this provider should only expose the interface described by the 
[generic Go GSSAPI specification](https://github.com/golang-auth/go-gssapi/v3).

Exposing provider-specific functionality (e.g., for configuring the underlying C library) is discouraged as it
dilutes the value of the provider independent interfaces. Such changes require careful review and should only be implemented when absolutely necessary.

Do not leak C-layer details (types, memory ownership, or lifecycle semantics) to consumers of the provider.


### Memory Management
As a wrapper around a C API, this provider must manage C-level memory internally and not expose details
such as pointers and memory management to callers.

#### Go references to memory allocated from C

Memory allocated by the C layer must be:
 * Released within provider code before returning to the caller, or
 * Attached to a provider-owned object (e.g., SecurityContext, GssName, Credential) with a clear, documented
   Free/Close/ Release method defined by the generic interface.

Use the appropriate GSS release functions for GSS-allocated resources (e.g., `gss_release_buffer`, `gss_release_name`, `gss_delete_sec_context`) instead of raw C.free where applicable.

Go variables allocated by C routines should be marked with a comment recording how and where it is freed.


#### C references to Go memory

Do not allow the C layer to hold references to Go memory beyond the duration of the C call.

The memory underlying a Go object must be _pinned_ to prevent the Go runtime from moving
or garbage collecting the object while C is accessing it.  Pointers passed directly to
C functions as arguments are automatically pinned by Go for the duration of the C call.
Pointers passed indirectly, as members of structs for example - are not, and must be pinned
by the caller or copied to memory allocated in C.

There is a generic (non-GSSAPI) example of memory pinning in `contrib/pinning` for anyone
new to the concept.

##### *Strings*

There are not many GSSAPI functions that take C `char *` strings as inputs.  In the few cases that do
require a null terminated string, use the CGO `CString` function to create a copy of the string in memory
owned by C, and be sure to free the memory, for example:

```go
        cName := C.CString(ccacheName)          // cName is a char *
        defer C.free(unsafe.Pointer(cName))     // free the allocated char * from C when Go is done with it

        cMinor := C.OM_uint32(0)
        cMajor := C._gogssapi_ccache_name(&cMinor, cName)
```

Alternatively, declare a wrapper function in the C preamble that takes a `_GoString_` parameter as described in
[C References to Go](https://pkg.go.dev/cmd/cgo#hdr-Go_references_to_C).

Do not attempt to pass memory underlying the Go string through any kind of unsafe operations - those require
reflection and the complexity and overhead generally outweighs simply copying the data.

##### *GSSAPI Buffers*

Most string and binary data is passed to GSSAPI routines using one of the GSSAPI buffer types such as `gss_buffer_desc`,
`gss_OID_desc` and `gss_OID_set_desc`.  While the memory underlying these structs themselves is automatically pinned, the
memory underlying member pointers is not and so passing these structs always involves an explicit pin operation or allocation within the C layer.

Some helper functions are provided for some common types:
 - `bytesToCBuffer(b []byte, pinner *runtime.Pinner) (C.gss_buffer_desc, *runtime.Pinner)`: returns a
   `gss_buffer_desc` struct with its value member pointing to the memory underlying the input byte slice, and its length
   member set to the length of the slice.  A new pinner is initialized and returned if the `pinner` argument is `nil`, and 
   the `Unpin()` method should be called on it when the C layer is done with the buffer.  If the `pinner` argument is non-
   nil, it will be used instead of creating a new pinner.

 - `gssOidSetFromOids(oids []g.Oid, pinner *runtime.Pinner) (C.gss_OID_set, *runtime.Pinner)`: returns a
   `gss_OID_set` (pointer to a `gss_OID_set_desc`) representing a C array of `gss_OID` pointers.  The provided
   `pinner` (or a new pinner if `pinner` is `nil`), is used to pin all of the memory underlying the OIDs.  The `Unpin()`
   method on the returned pinner should be called when the C layer is done with the OIDs.  A `nil` pointer is returned
   if the input OID list is empty, as required by the GSS API calls.

 - `oid2Coid(oid g.Oid, pinner *runtime.Pinner) (C.gss_OID, *runtime.Pinner)`: return a C `gss_OID` (pointer to a
   `gss_OID_desc`) representing the supplied `gssapi.Oid` (Go byte slice).  As with the other helpers, the supplied
   pinner is used to pin the memory underlying the `oid` argument - and a new pinner is used and returned if the
   `pinner` argument is nil.  The pinner should be used to `Unpin()` the memory once the C layer has done with the
   Oid.  Note that there are separate MacOS and non-MacOS versions of this helper to work around structure alignment
   issues on MacOS.


