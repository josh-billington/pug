// Package runner executes tools without a shell, with cancellation and bounded output.
package runner

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"time"

	"github.com/josh-billington/pug/internal/tools"
)

const MaxOutput = 16 << 20

type Invocation struct {
	Program string
	Args    []string
	Dir     string
	Env     []string
}

type Result struct {
	Stdout    []byte
	Stderr    []byte
	ExitCode  int
	Err       error
	Truncated bool
}

type Executor interface {
	Run(context.Context, Invocation) Result
}

type Local struct{}

type boundedBuffer struct {
	buffer    bytes.Buffer
	limit     int
	truncated bool
}

func (b *boundedBuffer) Write(data []byte) (int, error) {
	n := len(data)
	remaining := b.limit - b.buffer.Len()
	if n > remaining {
		data = data[:remaining]
		b.truncated = true
	}
	b.buffer.Write(data)
	return n, nil
}

func (Local) Run(ctx context.Context, invocation Invocation) Result {
	program, err := tools.LookPath(invocation.Program)
	if err != nil {
		return Result{ExitCode: -1, Err: err}
	}
	cmd := exec.CommandContext(ctx, program, invocation.Args...)
	cmd.Dir = invocation.Dir
	cmd.Env = invocation.Env
	cmd.WaitDelay = 2 * time.Second
	configureProcess(cmd)
	stdout := &boundedBuffer{limit: MaxOutput}
	stderr := &boundedBuffer{limit: 64 << 10}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err = cmd.Run()
	code := 0
	if err != nil {
		code = -1
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			code = exit.ExitCode()
		}
	}
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	return Result{Stdout: stdout.buffer.Bytes(), Stderr: stderr.buffer.Bytes(), ExitCode: code, Err: err, Truncated: stdout.truncated}
}
