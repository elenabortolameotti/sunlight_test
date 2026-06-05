package main

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

func main() {
	// Wait for server
	time.Sleep(1 * time.Second)

	client := &http.Client{Timeout: 5 * time.Second}
	
	urls := []string{
		"http://localhost:8080/ctlog/submit",
		"http://127.0.0.1:8080/ctlog/submit",
	}
	
	for _, url := range urls {
		req, _ := http.NewRequest("POST", url, nil)
		req.Header.Set("Host", "localhost:8080")
		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("URL: %s -> ERROR: %v\n", url, err)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		fmt.Printf("URL: %s -> Status: %d, Body: %s\n", url, resp.StatusCode, string(body))
	}
}
