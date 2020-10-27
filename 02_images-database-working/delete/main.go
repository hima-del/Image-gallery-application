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
	db, err = sql.Open("postgres", "postgres://himaja:password@localhost/image_gallery?sslmode=disable")
	if err != nil {
		panic(err)
	}
	err = db.Ping()
	if err != nil {
		panic(err)
	}
	fmt.Println("you are connected to database")
}

type Image struct {
	ID        int    `json:"id"`
	Label     string `json:"label"`
	Userid    int    `json:"userid"`
	Imagename string `json:"imagename"`
}

func main() {
	http.HandleFunc("/api/images", deleteImage)
	http.ListenAndServe(":8080", nil)
}

func deleteImage(w http.ResponseWriter, req *http.Request) {
	id := 3
	_, err := db.Query("delete from image where id=$1", id)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
}
