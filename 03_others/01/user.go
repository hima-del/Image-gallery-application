package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"

	_ "github.com/lib/pq"
)

var db *sql.DB
var tpl *template.Template

func init() {
	var err error
	db, err := sql.Open("postgres", "postgres://himaja:password@localhost/application?sslmode=disable")
	if err != nil {
		panic(err)
	}
	err = db.Ping()
	if err != nil {
		panic(err)
	}
	fmt.Println("you are connected to database")
	// stmt, err := db.Prepare("insert into userdetails(username,password)values('test', crypt('password', gen_salt('bf')))")
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// defer stmt.Close()
	// stmt.Exec()

	tpl = template.Must(template.ParseGlob("templates/*.gohtml"))
	tpl.ExecuteTemplate(w, "signup.gohtml", nil)

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
	fmt.Println("signup")
	if req.Method == http.MethodPost {
		fmt.Println("getting values")
		u.username = req.FormValue("username")
		u.password = req.FormValue("password")

		if u.username == "" || u.password == "" {
			http.Error(w, http.StatusText(400), http.StatusBadRequest)
			return
		}

		//u = User{username, password}
		_, err := db.Exec("insert into userdetails (username,password) values ($1,$2)", u.username, u.password)
		if err != nil {
			panic(err)
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"user": u.username,
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
}
