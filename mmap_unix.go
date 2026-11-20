//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package elfpatch

import (
	"os"
	"syscall"
)

// mapFile maps fh. Read-only maps are shared; writable ones are PRIVATE
// (copy-on-write), so edits never reach the file and only the pages an edit
// touches are copied.
func mapFile(fh *os.File, size int, write bool) ([]byte, func() error, error) {
	prot, flags := syscall.PROT_READ, syscall.MAP_SHARED
	if write {
		prot, flags = syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_PRIVATE
	}
	b, err := syscall.Mmap(int(fh.Fd()), 0, size, prot, flags)
	if err != nil {
		return nil, nil, err
	}
	return b, func() error { return syscall.Munmap(b) }, nil
}
