package runner

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// removalBackoff bounds how long cleanup waits for Docker's own --rm removal
// (about 4.5s in total) before declaring the container's absence unconfirmed.
var removalBackoff = []time.Duration{
	100 * time.Millisecond, 200 * time.Millisecond, 400 * time.Millisecond,
	800 * time.Millisecond, time.Second, time.Second, time.Second,
}

// RemoveContainer accepts Docker's automatic --rm cleanup only after verifying absence.
func RemoveContainer(ctx context.Context, executor Executor, name string) error {
	return removeContainer(ctx, executor, name, removalBackoff)
}

func removeContainer(ctx context.Context, executor Executor, name string, backoff []time.Duration) error {
	removed := executor.Run(ctx, Invocation{Program: "docker", Args: []string{"rm", "-f", name}})
	if removed.Err == nil && removed.ExitCode == 0 {
		return nil
	}
	// docker run --rm races this call: the container may already be gone or mid-removal.
	// Only those outcomes justify waiting; any other failure gets a single absence check.
	stderr := strings.ToLower(string(removed.Stderr))
	if !strings.Contains(stderr, "no such container") && !strings.Contains(stderr, "already in progress") {
		backoff = nil
	}
	for attempt := 0; ; attempt++ {
		remaining := executor.Run(ctx, Invocation{
			Program: "docker",
			Args:    []string{"ps", "-a", "--filter", "name=^/" + name + "$", "--format", "{{.ID}}"},
		})
		if remaining.Err != nil || remaining.ExitCode != 0 {
			return fmt.Errorf("could not confirm container cleanup: %s", name)
		}
		if strings.TrimSpace(string(remaining.Stdout)) == "" {
			return nil
		}
		if attempt >= len(backoff) {
			return fmt.Errorf("could not confirm container cleanup: %s", name)
		}
		timer := time.NewTimer(backoff[attempt])
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("could not confirm container cleanup: %s: %w", name, ctx.Err())
		case <-timer.C:
		}
	}
}
