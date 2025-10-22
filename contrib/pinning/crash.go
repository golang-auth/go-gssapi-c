package crash

/*

#include <stdio.h>

typedef struct test_struct {
	int a;
	char *b;
} test;

void testfunc1(const char *x) {
	fprintf(stderr, "Hello %s\n", x);
}

void testfunc2(test *x) {
	fprintf(stderr, "Hello %d : %s\n", x->a, x->b);
}

*/
import "C"
import (
	"runtime"
	"unsafe"
)

// test1() demonstrates that it is safe to pass a pointer to Go
// memory as the parameter to a C function.  The memory unerlying
// the parameter is automatically pinned for the duration of the C
// function execution.
func test1() {
	s1 := []byte{65, 66, 67, 0} // ABC

	s1bp := &s1[0]
	s1up := (*C.char)(unsafe.Pointer(s1bp))

	C.testfunc1(s1up)
}

// test2() demonstrates how Go memory pointers passed to C
// indirectly through struct members must be manually pinned.
func test2() {
	s1 := []byte{65, 66, 67, 0}

	s1bp := &s1[0]
	s1up := (*C.char)(unsafe.Pointer(s1bp))
	_ = s1up

	x := C.test{
		a: 123,
		b: s1up, // this is problematic
	}

	// This panics because x.b is (ie s1) is not pinned
	C.testfunc2(&x)
}

// test3() demonstrates how to pin indirectly passed Go memory
// pointers.
func test3() {
	s1 := []byte{65, 66, 67, 0}

	s1bp := &s1[0]
	s1up := (*C.char)(unsafe.Pointer(s1bp))

	pinner := runtime.Pinner{}
	pinner.Pin(s1bp)
	defer pinner.Unpin()

	x := C.test{
		a: 123,
		b: s1up,
	}

	// Does not panic because x.b is pinned by pinner
	C.testfunc2(&x)
}
