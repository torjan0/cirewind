//go:build darwin

package casefile

import "golang.org/x/sys/unix"

func publishDirectoryNoReplace(source, target string) error {
	return unix.RenamexNp(source, target, unix.RENAME_EXCL)
}
