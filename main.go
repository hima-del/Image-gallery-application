package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"

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
	// stmt, err := db.Prepare("insert into userdetails(username,password)values('test', crypt('password', gen_salt('bf')))")
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// defer stmt.Close()
	// stmt.Exec()
	tpl = template.Must(template.ParseGlob("templates/*.gohtml"))

}

const (
	app_key = "golangcode.com"
)

type User struct {
	//id       int    `json:"id"`
	username string `json:"username"`
	password []byte `json:"password"`
}

type Image struct {
	//id         int    `json:"id"`
	label      string `json:"title"`
	user_id    int    `json:"user_id"`
	image_name string `json:"image_name"`
}

func main() {
	//http.HandleFunc("/login", login)
	http.HandleFunc("/signup", signup)
	//http.HandleFunc("/images", getImages).Methods("GET")
	//http.HandleFunc("/images", postImages).Methods("POST")
	//http.HandleFunc("/images/:id", deleteImage).Methods("DELETE")
	http.ListenAndServe(":8080", nil)
}

func signup(w http.ResponseWriter, req *http.Request) {
	var u User
	if req.Method == http.MethodPost {
		//get form values
		username := req.FormValue("username")
		password := req.FormValue("password")

		//user already exists?
		rows, err := db.Query("select * from userdetails;")
		if err != nil {
			http.Error(w, http.StatusText(500), 500)
			return
		}
		defer rows.Close()
		users := make([]User, 0)
		for rows.Next() {
			ur := User{}
			err := rows.Scan(&ur.username, &ur.password)
			if err != nil {
				http.Error(w, http.StatusText(500), 500)
				return
			}
			users = append(users, ur)
		}
		if err = rows.Err(); err != nil {
			http.Error(w, http.StatusText(500), 500)
			return
		}
		for _, ur := range users {
			if ur.username == username {
				fmt.Println("user already exists")
			}
		}

		// if username != "myusername" || password != "mypassword" {
		// 	w.WriteHeader(http.StatusUnauthorized)
		// 	io.WriteString(w, `{"error":"invalid_credentials"}`)
		// 	return
		// }

		//when the credentials are ok we build a token and giving it an expiry of 1 hour
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"user": username,
			"exp":  time.Now().Add(time.Hour * time.Duration(1)).Unix(),
			"iat":  time.Now().Unix(),
		})
		tokenString, err := token.SignedString([]byte(app_key))
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			io.WriteString(w, `{"error":"token_generation_failed"}`)
			return
		}
		io.WriteString(w, `{"token":"`+tokenString+`"}`)
		return
		bs, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		u = User{username, bs}

	}
	tpl.ExecuteTemplate(w, "signup.gohtml", u)
}

// func login(w http.ResponseWriter, req *http.Request) {

// }
