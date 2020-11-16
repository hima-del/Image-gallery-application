package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	uuid "github.com/satori/go.uuid"
)

func extractToken(req *http.Request) string {
	bearToken := req.Header.Get("Authorization")
	stringArray := strings.Split(bearToken, " ")
	if len(stringArray) == 2 {
		return stringArray[1]
	}
	return ""
}

func checkBlacklist(w http.ResponseWriter, req *http.Request) string {
	tokenString := extractToken(req)
	result := db.QueryRow("select * from blacklist where token=$1", tokenString)
	var blacklistedToken string
	err := result.Scan(&blacklistedToken)
	if err != nil {
		return ""
	}
	return blacklistedToken
}

func verifyToken(w http.ResponseWriter, req *http.Request) (*jwt.Token, error) {
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

func tokenValid(w http.ResponseWriter, req *http.Request) error {
	token, err := verifyToken(w, req)
	if err != nil {
		return err
	}
	_, ok := token.Claims.(jwt.Claims)
	if !ok && !token.Valid {
		return err
	}
	return nil
}

func createToken(userid int, username string) (*TokenDetails, error) {
	var err error
	td := &TokenDetails{}
	td.ATExpires = time.Now().Add(time.Hour * 24).Unix()
	td.RTExpires = time.Now().Add(time.Hour * 24 * 7).Unix()
	AccessID, _ := uuid.NewV4()
	td.AccessUUID = AccessID.String()
	RefreshID, _ := uuid.NewV4()
	td.RefreshUUID = RefreshID.String()

	//creating access token
	os.Setenv("ACCESS_SECRET", "accesskey")
	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["access_uuid"] = td.AccessUUID
	atClaims["user_id"] = userid
	atClaims["username"] = username
	atClaims["exp"] = td.ATExpires
	pointerToAccessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	td.AccessToken, err = pointerToAccessToken.SignedString([]byte(os.Getenv("ACCESS_SECRET")))
	if err != nil {
		return nil, err
	}

	//creating refresh token
	os.Setenv("REFRESH_SECRET", "refreshkey")
	rtClaims := jwt.MapClaims{}
	rtClaims["refresh_uuid"] = td.RefreshUUID
	rtClaims["user_id"] = userid
	rtClaims["username"] = username
	rtClaims["exp"] = td.RTExpires
	pointerToRefreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, rtClaims)
	td.RefreshToken, err = pointerToRefreshToken.SignedString([]byte(os.Getenv("REFRESH_SECRET")))
	if err != nil {
		return nil, err
	}
	return td, nil
}

func createAccessToken(username interface{}) (*TokenDetails, error) {
	var err error
	at := &TokenDetails{}
	at.ATExpires = time.Now().Add(time.Hour * 24).Unix()
	AccessID, _ := uuid.NewV4()
	at.AccessUUID = AccessID.String()
	//creating new access token
	os.Setenv("ACCESS_SECRET", "newaccesssecret")
	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["access_uuid"] = at.AccessUUID
	atClaims["username"] = username
	atClaims["exp"] = at.ATExpires
	pointerToAccessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	at.AccessToken, err = pointerToAccessToken.SignedString([]byte(os.Getenv("ACCESS_SECRET")))
	if err != nil {
		return nil, err
	}
	return at, nil
}
