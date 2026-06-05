package main

import (
	"fmt"
	"net/http"
	"net/url"
)

func main() {
	prefix, _ := url.Parse("https://localhost:8080/ctlog")
	fmt.Printf("Host: %q\n", prefix.Host)
	fmt.Printf("Path: %q\n", prefix.Path)
	
	inner := http.NewServeMux()
	inner.HandleFunc("POST /submit", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "inner submit")
	})
	
	outer := http.NewServeMux()
	pattern := prefix.Host + prefix.Path + "/"
	fmt.Printf("Pattern: %q\n", pattern)
	outer.Handle(pattern, http.StripPrefix(prefix.Path, inner))
	
	// Also add a catch-all to see unmatched requests
	outer.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "catch-all: host=%q path=%q\n", r.Host, r.URL.Path)
	})
	
	fmt.Println("Starting on :8081")
	http.ListenAndServe(":8081", outer)
}
