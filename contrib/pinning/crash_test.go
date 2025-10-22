package crash

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTest1(t *testing.T) {
	test1()
}

func TestTest2(t *testing.T) {
	assert := assert.New(t)

	assert.Panics(test2)

	test3()
}
