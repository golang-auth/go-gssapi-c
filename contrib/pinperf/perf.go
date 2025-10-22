package pinperf

/*
#include <stdio.h>
#include <stdlib.h>

typedef struct test_struct {
	int a;
	char *b;
	char *c;
	char *d;
} test;

void testfunc(test *x) {
	fprintf(stdout , "Hello %d : %s\n", x->a, x->b);
}
*/
import "C"
import (
	"runtime"
	"unsafe"
)

func test1() {
	s1 := []byte{65, 66, 67, 0}
	s2 := []byte{68, 69, 70, 0}
	s3 := []byte{71, 72, 73, 0}

	s1bp := &s1[0]
	s1up := (*C.char)(unsafe.Pointer(s1bp))

	s2bp := &s2[0]
	s2up := (*C.char)(unsafe.Pointer(s2bp))

	s3bp := &s3[0]
	s3up := (*C.char)(unsafe.Pointer(s3bp))

	pinner := runtime.Pinner{}
	defer pinner.Unpin()
	pinner.Pin(s1bp)
	pinner.Pin(s2bp)
	pinner.Pin(s3bp)

	x := C.test{
		a: 123,
		b: s1up,
		c: s2up,
		d: s3up,
	}

	C.testfunc(&x)
}

func test2() {
	s1 := []byte{65, 66, 67, 0}

	s1c := C.CBytes(s1)
	defer C.free(s1c)
	s2c := C.CBytes(s1)
	defer C.free(s2c)
	s3c := C.CBytes(s1)
	defer C.free(s3c)

	x := C.test{
		a: 123,
		b: (*C.char)(s1c),
		c: (*C.char)(s2c),
		d: (*C.char)(s3c),
	}

	// Does not panic because x.b is pinned by pinner
	C.testfunc(&x)
}
