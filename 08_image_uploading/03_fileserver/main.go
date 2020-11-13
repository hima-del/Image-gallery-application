// // package main

// // import (
// // 	"io"
// // 	"net/http"
// // )

// // func main() {
// // 	http.HandleFunc("/", dog)
// // 	http.Handle("/resources/", http.StripPrefix("/resources", http.FileServer(http.Dir("./assets"))))
// // 	http.ListenAndServe(":8080", nil)
// // }

// // func dog(w http.ResponseWriter, req *http.Request) {
// // 	w.Header().Set("Content-Type", "text/html; charset=utf-8")
// // 	io.WriteString(w, `<img src="/resources/toby.jpg">`)
// // }

// // /*
// // ./assets/toby.jpg
// // */

// package main

// import (
// 	"io"
// 	"net/http"
// )

// func main() {
// 	http.Handle("/", http.FileServer(http.Dir(".")))
// 	http.HandleFunc("/dog/", dog)
// 	http.ListenAndServe(":8080", nil)
// }

// func dog(w http.ResponseWriter, req *http.Request) {
// 	w.Header().Set("Content-Type", "text/html; charset=utf-8")
// 	io.WriteString(w, `<img src="/toby.jpg">`)
// }
package main

import (
	"net/http"
)

func main() {
	//http.HandleFunc("/", dog)
	http.Handle("/assets/", http.StripPrefix("/assets", http.FileServer(http.Dir("./assets"))))
	http.ListenAndServe(":8080", nil)
}

// func dog(w http.ResponseWriter, req *http.Request) {
// 	w.Header().Set("Content-Type", "text/html; charset=utf-8")
// 	io.WriteString(w, `<img src="/assets/toby.jpg">`)
// }
