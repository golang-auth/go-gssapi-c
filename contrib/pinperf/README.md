# CGO Pinning performance

The benchmarks here demonstrate the difference between using 
[runtime.Pinner][runtime_pinner] and allocating and copying memory to
pass values from Go to C.

The example is a little contrived but does demonstrate that pinning
memory is more efficient that allocting memory, without even considering
the effects of heap fragmentation.

[runtime_pinner]: https://pkg.go.dev/runtime#Pinner "Runtime Pinner"