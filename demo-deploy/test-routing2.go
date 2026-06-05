package main

import (
	"fmt"
	"net/http"
)

func main() {
	inner := http.NewServeMux()
	inner.HandleFunc("POST /submit", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "inner submit")
	})
	
	outer := http.NewServeMux()
	outer.Handle("localhost:8081/ctlog/", http.StripPrefix("/ctlog", inner))
	outer.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "catch-all: host=%q path=%q\n", r.Host, r.URL.Path)
	})
	
	fmt.Println("Starting on :8081")
	http.ListenAndServe(":8081", outer)
}
