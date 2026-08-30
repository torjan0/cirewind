//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris && !windows

package casefile

import (
	"errors"
	"os"
)

func requireSingleLink(_ string, _ os.FileInfo) error {
	return errors.New("strict v0.2 case verification cannot establish hard link isolation on this platform")
}
