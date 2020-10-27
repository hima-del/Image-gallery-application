package main

import (
	"fmt"
	"strconv"
	"strings"
)

func main() {
	urlstr := "http://test.com/api/images/:3"
	// url, err := url.Parse(urlstr)
	// if err != nil {
	// 	fmt.Println(err)
	// }
	values := strings.TrimPrefix(urlstr, "http://test.com/api/images/:")
	// for i, v := range values {
	// 	if v == "id" {
	// 		fmt.Println(i)
	// 	}
	// }
	fmt.Println(values)
	fmt.Printf("%T", values)
	v, err := strconv.Atoi(values)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(v)
	fmt.Printf("%T", v)
}
