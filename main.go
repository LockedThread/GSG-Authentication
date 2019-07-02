package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
)

import _ "github.com/go-sql-driver/mysql"

const (
	host     = "localhost"
	user     = "gsgauth"
	password = "password"
	dbname   = "authentication"
)

func HelloServer(w http.ResponseWriter, req *http.Request) {
	log.Println(req.RequestURI)
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("This is an example server.\n"))
	data := GetMappedData(req.RequestURI, "/authentication")
	log.Println(data)

	i, err := strconv.ParseInt(data["id"], 10, 64)
	checkErr(err)

	user := GetUser(int(i))

	log.Println(user)
}

var mysql *sql.DB = nil

func main() {
	db, err := sql.Open("mysql", user+":"+password+"@tcp("+host+")/"+dbname /* "username:password@protocol(address)/dbname?param=value"*/)
	checkErr(err)

	mysql = db

	http.HandleFunc("/authentication", HelloServer)
	err = http.ListenAndServeTLS(":443", "server.crt", "server.key", nil)
	checkErr(err)
}

func GetUser(id int) User {
	var user User
	log.Println("id=", id)
	var resources string
	err := mysql.QueryRow("SELECT ID, Name, Resources FROM Users WHERE ID = ?", id).Scan(&user.ID, &user.Name, &resources)
	checkErr(err)
	log.Println("resources=" + resources)
	err = json.Unmarshal([]byte(resources), &user.Resources)
	checkErr(err)
	return user
}

func GetMappedData(raw string, handle string) map[string]string {
	substring := raw[len(handle)+1:]
	log.Println(substring)

	var dataMap = make(map[string]string)

	rootSplit := strings.Split(substring, "&")
	for e := range rootSplit {
		split := strings.Split(rootSplit[e], "=")
		dataMap[split[0]] = string(split[1])
	}

	return dataMap
}

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}
