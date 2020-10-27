package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"strings"

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
	http.HandleFunc("/api/images/id/", deleteImage)
	http.ListenAndServe(":8080", nil)
}

func deleteImage(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodDelete {
		http.Error(w, http.StatusText(405), http.StatusMethodNotAllowed)
		return
	}
	urlstring := req.URL.String()
	v := strings.TrimPrefix(urlstring, "/api/images/id/")
	id, err := strconv.Atoi(v)
	if v == "" {
		http.Error(w, http.StatusText(400), http.StatusBadRequest)
		return
	}
	_, err = db.Query("delete from image where id=$1", id)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
}
