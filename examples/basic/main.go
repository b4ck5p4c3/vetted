// One-shot Discover against the default RU allowlist endpoints.
// Prints the resolved v4 and v6 (one or both may be empty depending
// on the host's network) and the per-endpoint attempt table.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/b4ck5p4c3/vetted"
)

func main() {
	d := vetted.New(
		vetted.WithLogger(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))),
		vetted.WithTimeout(5*time.Second),
	)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res := d.Discover(ctx)

	fmt.Printf("v4 = %v (source=%s err=%v)\n", res.V4, res.V4Source, res.V4Err)
	fmt.Printf("v6 = %v (source=%s err=%v)\n", res.V6, res.V6Source, res.V6Err)
	fmt.Printf("\nattempts (%d):\n", len(res.Attempts))
	for _, a := range res.Attempts {
		status := "ok"
		if a.Err != nil {
			status = a.FailReason + " — " + a.Err.Error()
		}
		fmt.Printf("  %-12s %-3s cost=%-6d %4dms  http=%-3d  %s\n",
			a.Endpoint.Name, a.Family, a.Endpoint.Cost,
			a.Duration.Milliseconds(), a.HTTPStatus, status)
	}
}
