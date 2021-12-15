package main

import (
	"fmt"
	"log"
	"net/http"
)

// ReqestHandler handles HTTP requests
func RequestHandler(w http.ResponseWriter, r *http.Request) {
	data := fmt.Sprintf("%s method, %+v", r.Method, r)
	log.Println(data)
	w.Write([]byte(data))
}

// http server implementation
func main() {
	http.HandleFunc("/", RequestHandler)
	log.Fatal(http.ListenAndServe(":9999", nil))
}
