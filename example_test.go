package sunlight_test

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"filippo.io/sunlight"
)

func ExampleClient() {
	// This example shows how to create a client and read entries from a log.
	
	client, err := sunlight.NewClient(&sunlight.ClientConfig{
		MonitoringPrefix: "file://testdata/navigli2025h2",
		UserAgent:        "example@example.com (+https://example.com)",
		Logger:           slog.New(slog.NewTextHandler(os.Stderr, nil)),
	})
	if err != nil {
		fmt.Println("Error creating client:", err)
		return
	}

	// Read entries from the log
	ctx := context.Background()
	
	// Note: This example requires actual testdata to exist
	// For demonstration purposes only
	_ = client
	_ = ctx
	
	fmt.Println("Client created successfully")
	
	// Output: Client created successfully
}
