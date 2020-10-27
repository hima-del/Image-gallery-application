package main

import (
	"database/sql"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"

	"golang.org/x/crypto/bcrypt"

	_ "github.com/lib/pq"
)

var jwtKey = []byte("my_secret_key")

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

type Image struct {
	ID        int    `json:"id"`
	Label     string `json:"label"`
	Userid    int    `json:"userid"`
	Imagename string `json:"imagename"`
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
		_, err = db.Query("insert into userdetails (username,password)values ($1,$2)", creds.Username, string(hashedpassword))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		//declare the expiration time of the token
		//here we are adding 5mins
		expirationTime := time.Now().Add(5 * time.Minute)
		Claims := &Claims{
			Username: creds.Username,
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: expirationTime.Unix(),
			},
		}
		//declare token with algorithm used for signing
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims)
		//create jwt string
		tokenString, err := token.SignedString(jwtKey)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		//set client cookie for token as the jwt just generated
		http.SetCookie(w, &http.Cookie{
			Name:    "token",
			Value:   tokenString,
			Expires: expirationTime,
		})
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
		expirationTime := time.Now().Add(5 * time.Minute)
		Claims := &Claims{
			Username: creds.Username,
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: expirationTime.Unix(),
			},
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims)
		tokenString, err := token.SignedString(jwtKey)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:    "token",
			Value:   tokenString,
			Expires: expirationTime,
		})

	}
}

func getImages(w http.ResponseWriter, req *http.Request) {
	//obtain the session token from the request cookies which come with every request
	c, err := req.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			//cookie is not set
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		//for other errors return bad request status
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	//get the jwt string from cookie
	tknstr := c.Value

	//initialize new instance of claims
	claims := &Claims{}
	tkn, err := jwt.ParseWithClaims(tknstr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !tkn.Valid {
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

func refresh(w http.ResponseWriter, req *http.Request) {
	c, err := req.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	tknstr := c.Value
	claims := &Claims{}
	tkn, err := jwt.ParseWithClaims(tknstr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if !tkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if time.Unix(claims.ExpiresAt, 0).Sub(time.Now()) > 30*time.Second {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	//create a new token for the current use with a renewed expiration time
	expirationTime := time.Now().Add(5 * time.Minute)
	claims.ExpiresAt = expirationTime.Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenstring, err := token.SignedString(jwtKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	//set the new token as the users session_token cookie
	http.SetCookie(w, &http.Cookie{
		Name:    "session_token",
		Value:   tokenstring,
		Expires: expirationTime,
	})
}
