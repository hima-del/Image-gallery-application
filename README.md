
* Say you had a directory called /home/bob/static and you had this setup:

```
fs := http.FileServer(http.Dir("/home/bob/static"))
http.Handle("/static/", http.StripPrefix("/static", fs))
```
* Your server would take requests for e.g. `/static/foo/bar` and serve whatever is at `/home/bob/static/foo/bar`
