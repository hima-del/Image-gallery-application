package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"

	"golang.org/x/crypto/bcrypt"

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
	http.HandleFunc("/signup", signup)
	http.HandleFunc("/login", login)
	http.ListenAndServe(":8080", nil)
}

type Credentials struct {
	username string `json:"username"`
	password string `json:"password"`
}

func signup(w http.ResponseWriter, req *http.Request) {
	creds := &Credentials{}
	fmt.Println("signup")
	err := json.NewDecoder(req.Body).Decode(creds)
	if err != nil {
		fmt.Println("error")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	hashedpassword, err := bcrypt.GenerateFromPassword([]byte(creds.password), 8)
	fmt.Println("got password")
	_, err = db.Query("insert into userdetails (username,password)values ($1,$2)", creds.username, string(hashedpassword))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
}

func login(w http.ResponseWriter, req *http.Request) {
	creds := &Credentials{}
	err := json.NewDecoder(req.Body).Decode(creds)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	result := db.QueryRow("select password from userdetails where username=$1", creds.username)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	storedCreds := &Credentials{}
	err = result.Scan(&storedCreds.password)
	if err != nil {
		if err == sql.ErrNoRows {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err = bcrypt.CompareHashAndPassword([]byte(storedCreds.password), []byte(creds.password)); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
	}
}
