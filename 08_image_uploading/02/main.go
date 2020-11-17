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

	"golang.org/x/crypto/bcrypt"

	"github.com/dgrijalva/jwt-go"
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
	http.HandleFunc("/signup", cors(signup))
	http.HandleFunc("/login", cors(login))
	http.HandleFunc("/api/images/id/", cors(handleone))
	http.HandleFunc("/api/images/", cors(handletwo))
	http.HandleFunc("/logout", cors(logout))
	fs := http.FileServer(http.Dir("/home/ubuntu/images"))
	http.Handle("/images/", http.StripPrefix("/images", fs))
	http.ListenAndServe(":80", nil)
}

func cors(h http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		if r.Method == "OPTIONS" {
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
			return
		} else {
			h.ServeHTTP(w, r)
		}
	})
}

func handleone(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case "GET":
		getImage(w, req)
	case "DELETE":
		deleteImage(w, req)
	}
}

func handletwo(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case "GET":
		getImages(w, req)
	case "POST":
		createImage(w, req)
	}
}

type Credentials struct {
	ID       uint64 `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type Image struct {
	ID        uint64 `json:"id"`
	Label     string `json:"label"`
	Userid    int    `json:"userid"`
	Imagename string `json:"imagename"`
}
type Imageupload struct {
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
		if req.URL.Path != "/signup" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
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
		result := db.QueryRow("select username from userdetails where username=$1", creds.Username)
		storedCreds := &Credentials{}
		err = result.Scan(&storedCreds.Username)
		var s string = "username already taken"
		if storedCreds.Username != "" {
			stringdata, err := json.Marshal(s)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.Write(stringdata)
		} else {
			hashedpassword, err := bcrypt.GenerateFromPassword([]byte(creds.Password), 8)
			_, err = db.Query("insert into userdetails (username,password)values ($1,$2)", creds.Username, string(hashedpassword))
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			resultID := db.QueryRow("select id from userdetails where username=$1", creds.Username)
			var id int
			err = resultID.Scan(&id)
			//fmt.Println(id)
			token, err := createToken(id, creds.Username)
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
}

func login(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodPost {
		if req.URL.Path != "/login" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		beartoken := req.Header.Get("Authorization")
		if beartoken == "" {
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
			//if err = bcrypt.CompareHashAndPassword([]byte(storedCreds.Password), []byte(creds.Password)); err == nil {
			resultID := db.QueryRow("select id from userdetails where username=$1", creds.Username)
			fmt.Println(resultID)
			var id int
			err = resultID.Scan(&id)
			//fmt.Println("id", id)
			token, err := createToken(id, creds.Username)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			fmt.Println("access token length", len(token.AccessToken))
			fmt.Println("refresh token length", len(token.RefreshToken))
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
		} else if beartoken != "" {
			//fmt.Println("entered")
			tokenString := extractToken(req)
			claims := jwt.MapClaims{}
			token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
				return []byte("REFRESH_SECRET"), nil
			})
			fmt.Println(token)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			// ... error handling

			// do something with decoded claims
			for key, val := range claims {
				fmt.Printf("Key: %v, value: %v\n", key, val)
			}
			_, ok := claims["refresh_uuid"]
			if ok == true {
				idExtracted := claims["username"]
				//fmt.Println(id)
				newAccesstoken, err := createAccessToken(idExtracted)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				newToken := map[string]string{
					"access_token": newAccesstoken.AccessToken,
				}
				tokenData, err := json.Marshal(newToken)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				w.Write(tokenData)
			} else {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		}
	}
}

func getImage(w http.ResponseWriter, req *http.Request) {
	if req.Method != "GET" {
		http.Error(w, http.StatusText(405), http.StatusMethodNotAllowed)
		return
	}
	if req.URL.Path == "/api/images/id/" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	blacklistToken := checkBlacklist(w, req)
	if blacklistToken != "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	err := tokenValid(w, req)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	tokenString := extractToken(req)
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte("REFRESH_SECRET"), nil
	})
	fmt.Println(token)
	if err != nil {
		fmt.Println(err)
	}
	extrctedID := claims["user_id"]
	urlstring := req.URL.String()
	v := strings.TrimPrefix(urlstring, "/api/images/id/")
	id, err := strconv.Atoi(v)
	if v == "" || err != nil {
		http.Error(w, http.StatusText(400), http.StatusBadRequest)
		return
	}
	row := db.QueryRow("select * from image where id=$1 and user_id=$2", id, extrctedID)
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
	if req.URL.Path != "/api/images/" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	blacklistToken := checkBlacklist(w, req)
	if blacklistToken != "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	err := tokenValid(w, req)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	tokenString := extractToken(req)
	//fmt.Println("token", tokenString)
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte("REFRESH_SECRET"), nil
	})
	fmt.Println("parsed token", token)
	if err != nil {
		fmt.Println(err)
	}
	extrctedID := claims["user_id"]
	fmt.Println("id", extrctedID)
	rows, err := db.Query("select * from image where user_id=$1", extrctedID)
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
		if req.URL.Path != "/api/images/" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		req.ParseMultipartForm(10 << 20)
		blacklistToken := checkBlacklist(w, req)
		if blacklistToken != "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		err := tokenValid(w, req)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		l := req.FormValue("label")
		ui := req.FormValue("userid")
		i, _ := strconv.Atoi(ui)
		//uploading file
		file, header, err := req.FormFile("imagename")
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		defer file.Close()
		fmt.Println("uploaded file:", header.Filename)
		fmt.Println("file size:", header.Size)
		fmt.Println("MIME header:", header.Header)

		//tempFile, err := ioutil.TempFile("temp-images", "upload-*.png")
		tempFile, err := ioutil.TempFile("/home/ubuntu/images", "upload-*.png")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer tempFile.Close()

		fileBytes, err := ioutil.ReadAll(file)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		tempFile.Write(fileBytes)
		fmt.Fprintln(w, "successfully uploaded file")
		fileName := tempFile.Name()
		//v := strings.TrimPrefix(fileName, `temp-images\`)
		v := strings.TrimPrefix(fileName, `/home/ubuntu/images/`)
		images := Imageupload{l, i, v}
		images.Imagename = "http://13.59.20.19/images/" + images.Imagename
		tokenString := extractToken(req)
		claims := jwt.MapClaims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return []byte("REFRESH_SECRET"), nil
		})
		fmt.Println(token)
		if err != nil {
			fmt.Println(err)
		}
		extrctedID := claims["user_id"]
		fmt.Println("extracted id", extrctedID)
		stmnt := "insert into image (label,user_id,image_name)values ($1,$2,$3)"
		_, err = db.Exec(stmnt, images.Label, extrctedID, images.Imagename)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		resultpost := db.QueryRow("select id from image where image_name=$1", images.Imagename)
		var id int
		err = resultpost.Scan(&id)
		if err != nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		row := db.QueryRow("select * from image where id=$1 and user_id=$2", id, extrctedID)
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
}

func deleteImage(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodDelete {
		http.Error(w, http.StatusText(405), http.StatusMethodNotAllowed)
		return
	}
	if req.URL.Path == "/api/images/id/" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	blacklistToken := checkBlacklist(w, req)
	if blacklistToken != "" {
		w.WriteHeader(http.StatusUnauthorized)
	}
	err := tokenValid(w, req)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	tokenString := extractToken(req)
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte("REFRESH_SECRET"), nil
	})
	fmt.Println(token)
	if err != nil {
		fmt.Println(err)
	}
	extrctedID := claims["user_id"]
	urlstring := req.URL.String()
	v := strings.TrimPrefix(urlstring, "/api/images/id/")
	id, err := strconv.Atoi(v)
	if v == "" {
		http.Error(w, http.StatusText(400), http.StatusBadRequest)
		return
	}
	result := db.QueryRow("select image_name from image where id=$1", id)
	var deletedimage string
	err = result.Scan(&deletedimage)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	//imagename := "temp-images" + deletedimage
	imagename := "home/ubuntu/images/" + deletedimage
	err = os.Remove(imagename)
	_, err = db.Query("delete from image where id=$1 and user_id=$2", id, extrctedID)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
}

func logout(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodPost {
		blacklistToken := checkBlacklist(w, req)
		if blacklistToken != "" {
			w.WriteHeader(http.StatusUnauthorized)
		} else {
			err := tokenValid(w, req)
			if err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			tokenStringLogout := extractToken(req)
			stmnt := "insert into blacklist (token)values ($1)"
			_, err = db.Exec(stmnt, tokenStringLogout)
			if err != nil {
				log.Fatalln(err)
			}
			fmt.Println("succesfully logged out")
		}
	}
}
