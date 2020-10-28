package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
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
	ID        int    `json:"id"`
	Label     string `json:"label"`
	Userid    int    `json:"userid"`
	Imagename string `json:"imagename"`
}

func main() {
	http.HandleFunc("/api/images/", createImage)
	http.ListenAndServe(":8080", nil)
}

func createImage(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodPost {
		b, err := ioutil.ReadAll(req.Body)
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
		stmnt := "insert into image (id,label,user_id,image_name)values ($1,$2,$3,$4)"
		_, err = db.Exec(stmnt, images.ID, images.Label, images.Userid, images.Imagename)
		if err != nil {
			log.Fatalln(err)
		}
	}
}
