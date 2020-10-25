package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	_ "github.com/lib/pq"
)

var db *sql.DB

func init() {
	var err error
	db, err = sql.Open("postgres", "postgres://postgres:password@localhost/image_gallery?sslmode=disable")
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
	Label     string `json:"label"`
	Userid    int    `json:"userid"`
	Imagename string `json:"imagename"`
}

func main() {
	http.HandleFunc("/api/images/", createImage)
	http.ListenAndServe(":8080", nil)
}

func createImage(w http.ResponseWriter, req *http.Request) {
	fmt.Println("create image")
	if req.Method == http.MethodPost {
		fmt.Println(req.Body)
		b, err := ioutil.ReadAll(req.Body)
		fmt.Println(b)
		defer req.Body.Close()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		var images Image
		err = json.Unmarshal(b, &images)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, err = db.Query("insert into image(label,user_id,image_name)values($1,$2,$3)", images.Label, images.Userid, images.Imagename)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	}
}
