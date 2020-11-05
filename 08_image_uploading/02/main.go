package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
)

func main() {
	http.HandleFunc("/upload", uploadFile)
	http.ListenAndServe(":8080", nil)
}

func uploadFile(w http.ResponseWriter, req *http.Request) {
	req.ParseMultipartForm(10 << 20)
	file, header, err := req.FormFile("myfile")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer file.Close()
	fmt.Println("uploaded file:", header.Filename)
	fmt.Println("file size:", header.Size)
	fmt.Println("MIME header:", header.Header)

	tempFile, err := ioutil.TempFile("temp-images", "upload-*.png")
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

}
