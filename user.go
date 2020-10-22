package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"

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
	stmt, err := db.Prepare("insert into userdetails(username,password)values('test', crypt('password', gen_salt('bf')))")
	if err != nil {
		log.Fatal(err)
	}
	defer stmt.Close()
	stmt.Exec()

	tpl = template.Must(template.ParseGlob("templates/*.gohtml"))

}

var jwtKey = []byte("my_secret_key")

type User struct {
	username string `json:"username"`
	password string `json:"password"`
}

type Image struct {
	label      string `json:"title"`
	user_id    int    `json:"user_id"`
	image_name string `json:"image_name"`
}

func main() {
	http.HandleFunc("/signup", signup)
	http.ListenAndServe(":8080", nil)
}

func signup(w http.ResponseWriter, req *http.Request) {
	var u User
	if req.Method == http.MethodPost {
		username := req.FormValue("username")
		password := req.FormValue("password")
		u = User{username, password}
		// _, err := db.Exec("insert into userdetails (username,password) values ($1,$2)", u.username, u.password)
		// if err != nil {
		// 	panic(err)
		// }
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"user": username,
			"exp":  time.Now().Add(time.Hour * time.Duration(1)).Unix(),
			"iat":  time.Now().Unix(),
		})
		tokenString, err := token.SignedString(jwtKey)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			io.WriteString(w, `{"error":"token_generation_failed"}`)
			return
		}
		fmt.Fprintln(w, `{"token":"`+tokenString+`"}`)

	}
	tpl.ExecuteTemplate(w, "signup.gohtml", u)
}
