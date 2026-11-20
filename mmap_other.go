//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly)

package elfpatch

import (
	"io"
	"os"
)

// mapFile reads the whole file where there is no mmap; the "map" is a copy.
func mapFile(fh *os.File, size int, _ bool) ([]byte, func() error, error) {
	b := make([]byte, size)
	if _, err := io.ReadFull(io.NewSectionReader(fh, 0, int64(size)), b); err != nil {
		return nil, nil, err
	}
	return b, func() error { return nil }, nil
}
