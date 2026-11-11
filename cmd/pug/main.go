package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/josh-billington/pug/internal/cli"
)

var version = "dev"

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	code := cli.Execute(ctx, os.Args[1:], os.Stdout, os.Stderr, version)
	cancel()
	os.Exit(code)
}
