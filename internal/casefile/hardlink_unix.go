//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package casefile

import (
	"fmt"
	"os"
	"syscall"
)

// requireSingleLink rejects both case-internal and external hard links. A
// failed platform type assertion is an inability to establish isolation, so
// strict v0.2 verification fails closed.
func requireSingleLink(path string, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot establish hard link count for %q", path)
	}
	if stat.Nlink != 1 {
		return fmt.Errorf("strict v0.2 case file %q has hard link count %d; exactly one is required", path, stat.Nlink)
	}
	return nil
}
