package main

import "net/http"

func alreadyLoggedIn(req *http.Request) bool {
	c, err := req.Cookie("user")
	if err != nil {
		return false
	}

}
