//go:build !linux

package main

import (
	"errors"
	"syscall"
)

func setCongestion(syscall.RawConn, string) error {
	return errors.New("choosing a congestion control needs Linux")
}
