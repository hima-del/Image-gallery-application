package main

import (
	"fmt"
	"net/url"
)

func main() {
	s := "http://localhost:8080//api/:id/"
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	fmt.Println(u.RawFragment)
}
