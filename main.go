package main

import (
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

import _ "github.com/go-sql-driver/mysql"

const (
	host      = "localhost"
	port      = ":2096"
	user      = "gsgauth"
	password  = "password"
	dbname    = "authentication"
	userTable = "users"
	//resourcesTable = "resources"
	logTable     = "logs"
	responseData = "com.gameservergroup.gsgcore.AuthenticationTest:map:java.util.HashMap---com.gameservergroup.gsgcore.AuthenticationTest:list:java.util.ArrayList"
)

var (
	mysql               *sql.DB   = nil
	stmtSelectResources *sql.Stmt = nil
	stmtInsertLog       *sql.Stmt = nil
)

func AuthenticationResponseHandler(responseWriter http.ResponseWriter, request *http.Request) {
	query := request.URL.Query()

	println("query=", query.Encode())

	dataParam := query.Get("data")
	tokenParam := query.Get("token")
	resourceParam := query.Get("resource")

	if dataParam == "" || tokenParam == "" || resourceParam == "" {
		_, _ = responseWriter.Write([]byte("Suck my dick bitch boi, stop trying to hack me cuck"))
	} else {
		whitelistedResources := GetResources(tokenParam)
		requestedResource := resourceParam

		if CanUseResources(requestedResource, whitelistedResources) {
			var authenticationData AuthenticationData
			responseWriter.Header().Set("Content-Type", "text/plain")
			_, _ = responseWriter.Write([]byte(responseData))
			decodeString, err := base64.StdEncoding.DecodeString(dataParam)
			CheckErr(err)
			err = json.Unmarshal([]byte(decodeString), &authenticationData)
			CheckErr(err)
			authenticationData.ToString()
			LogAuthentcation(tokenParam, authenticationData)
		} else {
			_, _ = responseWriter.Write([]byte("Suck my dick bitch boi, stop trying to hack me cuck"))
		}
	}
}

func CanUseResources(resource string, resources []string) bool {
	if resource == "" || resources == nil {
		return false
	}
	for e := range resources {
		s := resources[e]
		if s == resource || s == "*" {
			return true
		}
	}
	return false
}

func main() {
	db, err := sql.Open("mysql", user+":"+password+"@tcp("+host+")/"+dbname)
	CheckErr(err)

	mysql = db

	InitPreparedStatements()

	mux := http.NewServeMux()
	mux.HandleFunc("/authentication", AuthenticationResponseHandler)
	cfg := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	}
	mux.HandleFunc("/favicon.ico", func(responseWriter http.ResponseWriter, request *http.Request) {
		responseWriter.Header().Set("Content-Type", "text/plain")
		_, _ = responseWriter.Write([]byte("How you get here?"))
	})
	srv := &http.Server{

		Addr:         port,
		Handler:      mux,
		TLSConfig:    cfg,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
	}
	log.Fatal(srv.ListenAndServeTLS("server.crt", "server.key"))
}

func InitPreparedStatements() {
	stmt, err := mysql.Prepare("SELECT resources FROM " + userTable + " WHERE token = ?")
	CheckErr(err)
	stmtSelectResources = stmt
	stmt, err = mysql.Prepare("INSERT INTO " + logTable + " (token, resource, ip_address, os_name, os_arch, os_version, user_name, computer_name, processor_identifier, processor_architecture, number_of_processors, operators) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
	CheckErr(err)
	stmtInsertLog = stmt
}

func LogAuthentcation(token string, data AuthenticationData) {
	bytes, err := json.Marshal(data.Operators)
	CheckErr(err)
	_, err = stmtInsertLog.Exec(token, data.Resource, data.IPAddress, data.OsName, data.OsArch, data.OsVersion, data.UserName, data.ComputerName, data.ProcessorIdentifier, data.ProcessorArchitecture, data.NumberOfProcessors, string(bytes))
	CheckErr(err)
}

func GetResources(token string) []string {
	var resourcesString string
	err := stmtSelectResources.QueryRow(token).Scan(&resourcesString)
	if err != nil {
		println(err)
		return nil
	}
	var resourcesArray []string
	err = json.Unmarshal([]byte(resourcesString), &resourcesArray)
	if err != nil {
		println(err)
		return nil
	}
	return resourcesArray
}

func CheckErr(err error) {
	if err != nil {
		panic(err)
	}
}

type AuthenticationData struct {
	Resource              string   `json:"resource"`
	IPAddress             string   `json:"ipAddress"`
	OsName                string   `json:"osName"`
	OsArch                string   `json:"osArch"`
	OsVersion             string   `json:"osVersion"`
	UserName              string   `json:"userName"`
	ProcessorIdentifier   string   `json:"processorIdentifier"`
	ComputerName          string   `json:"computerName"`
	ProcessorArchitecture string   `json:"processorArchitecture"`
	NumberOfProcessors    int      `json:"numberOfProcessors"`
	Operators             []string `json:"operators"`
}

func (a AuthenticationData) ToString() {
	fmt.Printf("%+v\n", a)
}
