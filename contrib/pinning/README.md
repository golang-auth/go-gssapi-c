# CGO Pinning example

This is an example of when it is necessary to explicity pin memory passed from
Go to C.  Pinning memory prevents the Go runtime from moving or garbage collecting
the object while it is pinned.

 - `test1()`: shows a byte slice being passed to Go as a `const char *`
   value.  The memory underlying the slice is automatically pinned by the Go
   runtime for the duration of the C call, because it is passed as an argument
   to a C function.

 - `test2()`: this function panics because the memory underlying the byte slice
   is passed to C as a member of a struct.  The struct itself is pinned by
   the Go runtime but its members are not.

- `test3()`: demonstrated the correct way to pass Go memory to C indirectly
  as a member of a struct.  A [runtime.Pinner][runtime_pinner] is used to
  explicitly prevent the memory being moved or garbage collected.


[runtime_pinner]: https://pkg.go.dev/runtime#Pinner "Runtime Pinner"