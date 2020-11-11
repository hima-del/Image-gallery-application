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
	http.HandleFunc("/api/images/id/", handleone)
	http.HandleFunc("/api/images/", handletwo)
	http.HandleFunc("/logout", logout)
	http.Handle("/", http.FileServer(http.Dir("./temp-images")))
	http.ListenAndServe(":80", nil)
}
func setupResponse(w http.ResponseWriter, req *http.Request) {
	(w).Header().Set("Access-Control-Allow-Origin", "*")
	(w).Header().Set("Access-Control-Allow-Credentials", "true")
	(w).Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	(w).Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization,accept, origin, Cache-Control, X-Requested-With")
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
		setupResponse(w, req)
		if req.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
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
		if storedCreds.Username != "" {
			fmt.Fprintln(w, "username already taken")
		} else {
			hashedpassword, err := bcrypt.GenerateFromPassword([]byte(creds.Password), 8)
			_, err = db.Query("insert into userdetails (username,password)values ($1,$2)", creds.Username, string(hashedpassword))
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			token, err := createToken(creds.ID, creds.Username)
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
		setupResponse(w, req)
		if req.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
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
		beartoken := req.Header.Get("Authorization")
		if beartoken != "" && len(beartoken) == 162 {
			newAccesstoken, err := createAccessToken(creds.ID)
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
		} else if beartoken == "" {
			if err = bcrypt.CompareHashAndPassword([]byte(storedCreds.Password), []byte(creds.Password)); err == nil {
				token, err := createToken(creds.ID, creds.Username)
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
}

func getImage(w http.ResponseWriter, req *http.Request) {
	if req.Method != "GET" {
		http.Error(w, http.StatusText(405), http.StatusMethodNotAllowed)
		return
	}
	setupResponse(w, req)
	if req.Method == "OPTIONS" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	token := checkBlacklist(w, req)
	if token != "" {
		w.WriteHeader(http.StatusUnauthorized)
	} else {
		err := tokenValid(w, req)
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
}

func getImages(w http.ResponseWriter, req *http.Request) {
	if req.Method != "GET" {
		http.Error(w, http.StatusText(405), http.StatusMethodNotAllowed)
		return
	}
	setupResponse(w, req)
	if req.Method == "OPTIONS" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	token := checkBlacklist(w, req)
	if token != "" {
		w.WriteHeader(http.StatusUnauthorized)
	} else {
		err := tokenValid(w, req)
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
}

func createImage(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodPost {
		setupResponse(w, req)
		if req.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		req.ParseMultipartForm(10 << 20)
		token := checkBlacklist(w, req)
		if token != "" {
			w.WriteHeader(http.StatusUnauthorized)
		} else {
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
				fmt.Println(err)
				return
			}
			defer file.Close()
			fmt.Println("uploaded file:", header.Filename)
			fmt.Println("file size:", header.Size)
			fmt.Println("MIME header:", header.Header)

			//tempFile, err := ioutil.TempFile("/d/training-project-repo/Image-gallery-application/08_image_uploading/02/temp-images", "upload-*.png")
			tempFile, err := ioutil.TempFile("/home/ubuntu/images", "upload-*.png")
			if err != nil {
				fmt.Println(err)
			}
			defer tempFile.Close()

			fileBytes, err := ioutil.ReadAll(file)
			if err != nil {
				fmt.Println(err)
			}
			tempFile.Write(fileBytes)
			fmt.Fprintln(w, "successfully uploaded file")
			fileName := tempFile.Name()
			// v := strings.TrimPrefix(fileName, `temp-images\`)
			v := strings.TrimPrefix(fileName, `/home/ubuntu/images/`)
			images := Imageupload{l, i, v}
			images.Imagename = "http://13.59.20.19/" + images.Imagename
			stmnt := "insert into image (label,user_id,image_name)values ($1,$2,$3)"
			_, err = db.Exec(stmnt, images.Label, images.Userid, images.Imagename)
			if err != nil {
				log.Fatalln(err)
			}
		}
	}
}

func deleteImage(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodDelete {
		http.Error(w, http.StatusText(405), http.StatusMethodNotAllowed)
		return
	}
	setupResponse(w, req)
	if req.Method == "OPTIONS" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	token := checkBlacklist(w, req)
	if token != "" {
		w.WriteHeader(http.StatusUnauthorized)
	} else {
		err := tokenValid(w, req)
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
		result := db.QueryRow("select image_name from image where id=$1", id)
		var deletedimage string
		err = result.Scan(&deletedimage)
		// imagename := "/d/training-project-repo/Image-gallery-application/08_image_uploading/02/temp-images/" + deletedimage
		imagename := "home/ubuntu/images/" + deletedimage
		err = os.Remove(imagename)
		_, err = db.Query("delete from image where id=$1", id)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
	}
}

func logout(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodPost {
		setupResponse(w, req)
		if req.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		token := checkBlacklist(w, req)
		if token != "" {
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
