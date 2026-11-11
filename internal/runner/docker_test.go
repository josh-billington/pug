package runner

import (
	"context"
	"errors"
	"testing"
	"time"
)

type dockerExecutor func(context.Context, Invocation) Result

func (f dockerExecutor) Run(ctx context.Context, i Invocation) Result { return f(ctx, i) }

func TestContainerCleanup(t *testing.T) {
	t.Parallel()
	inProgress := Result{ExitCode: 1, Err: errors.New("exit status 1"),
		Stderr: []byte("Error response from daemon: removal of container pug-test is already in progress")}
	noSuch := Result{ExitCode: 1, Err: errors.New("exit status 1"),
		Stderr: []byte("Error response from daemon: No such container: pug-test")}
	other := Result{ExitCode: 1, Err: errors.New("not found")}
	present := Result{Stdout: []byte("container-id\n")}
	cases := []struct {
		name     string
		removal  Result
		listings []Result
		wantErr  bool
		wantPS   int
	}{
		{name: "rm succeeds", removal: Result{}, wantPS: 0},
		{name: "already removed", removal: other, listings: []Result{{}}, wantPS: 1},
		{name: "still running", removal: other, listings: []Result{present}, wantErr: true, wantPS: 1},
		{name: "daemon unavailable", removal: other, listings: []Result{{ExitCode: 1, Err: errors.New("offline")}}, wantErr: true, wantPS: 1},
		{name: "no such container", removal: noSuch, listings: []Result{{}}, wantPS: 1},
		{name: "removal in progress then gone", removal: inProgress, listings: []Result{present, present, {}}, wantPS: 3},
		{name: "removal in progress never finishes", removal: inProgress, listings: []Result{present, present, present, present}, wantErr: true, wantPS: 3},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ps := 0
			executor := dockerExecutor(func(_ context.Context, i Invocation) Result {
				if i.Args[0] == "rm" {
					return tt.removal
				}
				ps++
				return tt.listings[min(ps, len(tt.listings))-1]
			})
			err := removeContainer(t.Context(), executor, "pug-test", []time.Duration{time.Millisecond, time.Millisecond})
			if (err != nil) != tt.wantErr {
				t.Fatalf("cleanup error = %v, want error=%t", err, tt.wantErr)
			}
			if ps != tt.wantPS {
				t.Fatalf("docker ps calls = %d, want %d", ps, tt.wantPS)
			}
		})
	}
}

func TestContainerCleanupHonoursContext(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	executor := dockerExecutor(func(_ context.Context, i Invocation) Result {
		if i.Args[0] == "rm" {
			return Result{ExitCode: 1, Err: errors.New("exit status 1"), Stderr: []byte("removal is already in progress")}
		}
		cancel()
		return Result{Stdout: []byte("container-id")}
	})
	err := removeContainer(ctx, executor, "pug-test", []time.Duration{time.Hour})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cleanup error = %v, want context cancellation", err)
	}
}
