package main

import (
	"fmt"
	"os"
)

func main() {
	f, err := os.Create("image.text")
	if err != nil {
		fmt.Println(err)
	}
	defer f.Close()
	fmt.Println(f)
}
