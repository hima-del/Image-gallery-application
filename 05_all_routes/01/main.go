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
	"time"

	uuid "github.com/satori/go.uuid"

	"github.com/dgrijalva/jwt-go"

	"golang.org/x/crypto/bcrypt"

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

func main() {
	http.HandleFunc("/signup", signup)
	http.HandleFunc("/login", login)
	http.HandleFunc("/api/images/id/", getImage)
	http.HandleFunc("/api/images/", getImages)
	http.HandleFunc("/api/images/", createImage)
	http.HandleFunc("/api/images/id/", deleteImage)
	http.ListenAndServe(":8080", nil)
}

type Credentials struct {
	ID       uint64 `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type Image struct {
	ID        int    `json:"id"`
	Label     string `json:"label"`
	Userid    int    `json:"userid"`
	Imagename string `json:"imagename"`
}

type TokenDetails struct {
	AccessToken  string
	RefreshToken string
	AccessUUID   string
	RefreshUUID  string
	ATExpires    int64
	RTExpires    int64
}

func signup(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodPost {
		b, err := ioutil.ReadAll(req.Body)
		defer req.Body.Close()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		var creds Credentials
		err = json.Unmarshal(b, &creds)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		hashedpassword, err := bcrypt.GenerateFromPassword([]byte(creds.Password), 8)
		_, err = db.Query("insert into userdetails (id,username,password)values ($1,$2,$3)", creds.ID, creds.Username, string(hashedpassword))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		token, err := createToken(creds.ID)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		tokens := map[string]string{
			"acces_token":   token.AccessToken,
			"refresh_token": token.RefreshToken,
		}
		data, err := json.Marshal(tokens)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Write(data)
	}
}

func login(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodPost {
		creds := &Credentials{}
		err := json.NewDecoder(req.Body).Decode(creds)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		result := db.QueryRow("select password from userdetails where username=$1", creds.Username)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		storedCreds := &Credentials{}
		err = result.Scan(&storedCreds.Password)
		if err != nil {
			if err == sql.ErrNoRows {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if err = bcrypt.CompareHashAndPassword([]byte(storedCreds.Password), []byte(creds.Password)); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
		}
		token, err := createToken(creds.ID)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		tokens := map[string]string{
			"acces_token":   token.AccessToken,
			"refresh_token": token.RefreshToken,
		}
		data, err := json.Marshal(tokens)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Write(data)
	}
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

func createToken(userid uint64) (*TokenDetails, error) {
	var err error
	td := &TokenDetails{}
	td.ATExpires = time.Now().Add(time.Minute * 15).Unix()
	AccessID, err := uuid.NewV4()
	td.AccessUUID = AccessID.String()
	RefreshID, err := uuid.NewV4()
	td.RefreshUUID = RefreshID.String()

	//creating access token
	os.Setenv("ACCESS_SECRET", "lkrdjgjzjlgj")
	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["access_uuid"] = td.AccessUUID
	atClaims["user_id"] = userid
	atClaims["exp"] = td.ATExpires
	pointerToAccessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	td.AccessToken, err = pointerToAccessToken.SignedString([]byte(os.Getenv("ACCESS_SECRET")))
	if err != nil {
		return nil, err
	}

	//creating refresh token
	os.Setenv("REFRESH_SECRET", "jgsuygsghbb")
	rtClaims := jwt.MapClaims{}
	rtClaims["refresh_uuid"] = td.RefreshUUID
	atClaims["user_id"] = userid
	atClaims["exp"] = td.RTExpires
	pointerToRefreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, rtClaims)
	td.RefreshToken, err = pointerToRefreshToken.SignedString([]byte(os.Getenv("REFRESH_SECRET")))
	if err != nil {
		return nil, err
	}
	return td, nil
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
