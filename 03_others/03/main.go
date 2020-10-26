package main

import (
	"database/sql"
	//"encoding/json"
	"fmt"
	"html/template"
	"net/http"

	//"golang.org/x/crypto/bcrypt"

	_ "github.com/lib/pq"
)

var db *sql.DB
var tpl *template.Template

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

func main() {
	http.HandleFunc("/signin", Signin)
	http.HandleFunc("/signup", Signup)
	http.ListenAndServe(":8080", nil)
}
