//go:build unix

package hostmetrics

import "golang.org/x/sys/unix"

// diskUsage reports the usage of the filesystem holding path. Statfs is the
// only part of this package that is a syscall rather than a file in /proc.
func diskUsage(path string) (used, total uint64) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return 0, 0
	}
	blockSize := uint64(stat.Bsize)
	total = stat.Blocks * blockSize
	// Bavail, not Bfree: the reserved blocks only root can use are not space
	// anything on this node can actually have.
	free := stat.Bavail * blockSize
	if free > total {
		return 0, total
	}
	return total - free, total
}
