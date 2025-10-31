package runtime

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// WithSignalHandler returns a context cancelled on SIGINT or SIGTERM.
func WithSignalHandler(parent context.Context) context.Context {
	ctx, cancel := context.WithCancel(parent)
	ch := make(chan os.Signal, 2)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		defer signal.Stop(ch)
		select {
		case <-ch:
			cancel()
		case <-parent.Done():
			cancel()
		}
	}()

	return ctx
}
