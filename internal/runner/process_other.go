//go:build !unix

package runner

import "os/exec"

// shortcut: non-Unix cancellation kills the direct child only; use a job object for Windows process trees.
func configureProcess(cmd *exec.Cmd) {}
