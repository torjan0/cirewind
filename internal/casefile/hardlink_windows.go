//go:build windows

package casefile

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

func requireSingleLink(path string, _ os.FileInfo) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %q for hard link inspection: %w", path, err)
	}
	defer file.Close()
	var details windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &details); err != nil {
		return fmt.Errorf("cannot establish hard link count for %q: %w", path, err)
	}
	if details.NumberOfLinks != 1 {
		return fmt.Errorf("strict v0.2 case file %q has hard link count %d; exactly one is required", path, details.NumberOfLinks)
	}
	return nil
}
