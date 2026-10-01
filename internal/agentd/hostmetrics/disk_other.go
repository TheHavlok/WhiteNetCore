//go:build !unix

package hostmetrics

// diskUsage has no implementation off unix. The agent only ever runs on Linux
// nodes; this exists so the package still builds on a Windows workstation.
func diskUsage(string) (used, total uint64) { return 0, 0 }
