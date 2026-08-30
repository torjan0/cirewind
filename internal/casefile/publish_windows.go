//go:build windows

package casefile

import "golang.org/x/sys/windows"

func publishDirectoryNoReplace(source, target string) error {
	from, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	// MoveFileEx without MOVEFILE_REPLACE_EXISTING is the Windows no-replace
	// publication primitive. WRITE_THROUGH asks the system not to report
	// success before the move has reached durable storage.
	return windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH)
}
