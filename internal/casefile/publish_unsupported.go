//go:build !linux && !darwin && !windows

package casefile

import "errors"

func publishDirectoryNoReplace(_, _ string) error {
	return errors.New("atomic no-replace case publication is unsupported on this platform")
}
