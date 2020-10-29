package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/dgrijalva/jwt-go"

	_ "github.com/lib/pq"
)

type Image struct {
	ID        int    `json:"id"`
	Label     string `json:"label"`
	Userid    int    `json:"userid"`
	Imagename string `json:"imagename"`
}

func getImage(w http.ResponseWriter, req *http.Request) {
	if req.Method != "GET" {
		http.Error(w, http.StatusText(405), http.StatusMethodNotAllowed)
		return
	}

	err := tokenValid(req)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	urlstring := req.URL.String()
	v := strings.TrimPrefix(urlstring, "/api/images/id/")
	id, err := strconv.Atoi(v)
	if v == "" {
		http.Error(w, http.StatusText(400), http.StatusBadRequest)
		return
	}
	row := db.QueryRow("select * from image where id=$1", id)
	img := Image{}
	err = row.Scan(&img.ID, &img.Label, &img.Userid, &img.Imagename)
	switch {
	case err == sql.ErrNoRows:
		http.NotFound(w, req)
		return
	case err != nil:
		http.Error(w, http.StatusText(500), http.StatusInternalServerError)
		return
	}
	js, err := json.Marshal(img)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(js)
}

func getImages(w http.ResponseWriter, req *http.Request) {
	if req.Method != "GET" {
		http.Error(w, http.StatusText(405), http.StatusMethodNotAllowed)
		return
	}

	err := tokenValid(req)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

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

func createImage(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodPost {
		err := tokenValid(req)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
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

func deleteImage(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodDelete {
		http.Error(w, http.StatusText(405), http.StatusMethodNotAllowed)
		return
	}
	err := tokenValid(req)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
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

func logout(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodPost {
		err := tokenValid(req)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		//bearToken := req.Header.Get("Authorization")
		//fmt.Println(bearToken)
		req.Header.Del("Authorization")
		fmt.Println("logged out")
	}
}

func extractToken(req *http.Request) string {
	bearToken := req.Header.Get("Authorization")
	stringArray := strings.Split(bearToken, " ")
	if len(stringArray) == 2 {
		return stringArray[1]
	}
	return ""
}

func verifyToken(req *http.Request) (*jwt.Token, error) {
	tokenString := extractToken(req)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodHMAC)
		if !ok {
			return nil, fmt.Errorf("unexpected signing method:%v", token.Header["alg"])
		}
		return []byte(os.Getenv("ACCESS_SECRET")), nil
	})
	if err != nil {
		return nil, err
	}
	return token, nil
}

func tokenValid(req *http.Request) error {
	token, err := verifyToken(req)
	if err != nil {
		return err
	}
	_, ok := token.Claims.(jwt.Claims)
	if !ok && !token.Valid {
		return err
	}
	return nil
}
