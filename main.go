package main

import (
	"database/sql"
	"fmt"
	"net/http"

	_ "github.com/lib/pq"
)

var db *sql.DB

func init() {
	var err error
	db, err := sql.Open("postgres", "postgres://himaja:password@localhost/image_gallery?sslmode=disable")
	if err != nil {
		panic(err)
	}
	err = db.Ping()
	if err != nil {
		panic(err)
	}
	fmt.Println("you are connected to database")
}

type Userdetails struct {
	id       int    `json:"id"`
	username string `json:"username"`
	password string `json:"password"`
}

type Image struct {
	id         int    `json:"id"`
	label      string `json:"title"`
	user_id    int    `json:"user_id"`
	image_name string `json:"image_name"`
}

func main() {
	http.HandleFunc("/login", login)
	http.HandleFunc("/signup", signup)
	http.HandleFunc("/images", getImages).Methods("GET")
	http.HandleFunc("/images", postImages).Methods("POST")
	http.HandleFunc("/images/:id", deleteImage).Methods("DELETE")
}

func signup(w http.ResponseWriter, req *http.Request) {
	u := req.FormValue("username")
	p := req.FormValue("password")

}
