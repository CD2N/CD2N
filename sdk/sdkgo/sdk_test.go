package sdkgo_test

import (
	"testing"

	"github.com/pkg/errors"
)

var (
	ErrorNotFound = errors.New("not found")
)

func TestErrorWarp(t *testing.T) {
	err := errors.Wrap(ErrorNotFound, "test error warp")
	t.Log(errors.Unwrap(errors.Unwrap(err)))
}
