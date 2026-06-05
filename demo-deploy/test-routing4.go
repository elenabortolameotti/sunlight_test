package main

import (
	"fmt"
	"net/http"
)

func main() {
	inner := http.NewServeMux()
	inner.HandleFunc("POST /submit", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "inner submit: host=%q path=%q\n", r.Host, r.URL.Path)
	})
	
	outer := http.NewServeMux()
	outer.Handle("localhost:8083/ctlog/", http.StripPrefix("/ctlog", inner))
	outer.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "catch-all: host=%q path=%q\n", r.Host, r.URL.Path)
	})
	
	fmt.Println("Starting on :8083")
	http.ListenAndServe(":8083", outer)
}
