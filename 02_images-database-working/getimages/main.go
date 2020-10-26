package main

import (
	"database/sql"
	"encoding/json"
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
	http.HandleFunc("/api/images/", getImages)
	http.ListenAndServe(":8080", nil)
}

func getImages(w http.ResponseWriter, req *http.Request) {
	rows, err := db.Query("select * from image")
	if err != nil {
		http.Error(w, http.StatusText(500), 500)
		return
	}
	defer rows.Close()
	images := make([]Image, 0)
	for rows.Next() {
		img := Image{}
		err := rows.Scan(&img.ID, &img.Label, &img.Userid, &img.Imagename)
		if err != nil {
			http.Error(w, http.StatusText(500), 500)
			return
		}
		images = append(images, img)
	}
	if err = rows.Err(); err != nil {
		http.Error(w, http.StatusText(500), 500)
		return
	}
	js, err := json.Marshal(images)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(js)
}
