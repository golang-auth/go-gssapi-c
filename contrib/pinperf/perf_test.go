package pinperf

import (
	"testing"
)

func BenchmarkPinning(b *testing.B) {
	for b.Loop() {
		test1()
	}
}

func BenchmarkCopying(b *testing.B) {
	for b.Loop() {
		test2()
	}
}
