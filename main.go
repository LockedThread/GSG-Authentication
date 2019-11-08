package main

import (
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
)

import _ "github.com/go-sql-driver/mysql"

var (
	mysql                            *sql.DB   = nil
	stmtSelectResourcesFromUserTable *sql.Stmt = nil
	stmtInsertLog                    *sql.Stmt = nil
	stmtSelectResponseData           *sql.Stmt = nil
)
var config *Config

func main() {
	config = config.SetupConfig()
	db, err := sql.Open("mysql", config.User+":"+config.Password+"@tcp("+config.Host+")/"+config.DbName)
	CheckErr(err)

	mysql = db

	CreateTables()
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

		Addr:         "0.0.0.0:8443",
		Handler:      mux,
		TLSConfig:    cfg,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
	}

	fmt.Println("Bot is now running.  Press CTRL-C to exit.")
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		_ = mysql.Close()
		os.Exit(1)
	}()
	err = srv.ListenAndServeTLS("server.crt", "server.key")
	CheckErr(err)
}

func AuthenticationResponseHandler(responseWriter http.ResponseWriter, request *http.Request) {
	query := request.URL.Query()

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
			decodeString, err := base64.StdEncoding.DecodeString(dataParam)
			CheckErr(err)
			err = json.Unmarshal(decodeString, &authenticationData)
			CheckErr(err)
			authenticationData.ToString()
			LogAuthentication(tokenParam, authenticationData)
			queryRow := stmtSelectResponseData.QueryRow(resourceParam)
			var responseData string
			err = queryRow.Scan(&responseData)
			if err != nil {
				_, _ = responseWriter.Write([]byte("Dd-d-d-d-d-d-done"))
			} else {
				_, _ = responseWriter.Write([]byte(responseData))
			}
		} else {
			_, _ = responseWriter.Write([]byte("Suck my dick bitch boi, stop trying to hack me cuck"))
		}
	}
}

func CreateTables() {
	_, err := mysql.Exec("CREATE TABLE IF NOT EXISTS " + config.Tables.LogTable + " (id INT AUTO_INCREMENT NOT NULL, time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,token varchar(12) NOT NULL,resource varchar(255) NOT NULL,ip_address varchar(255) NOT NULL,os_name varchar(255) NOT NULL,os_arch varchar(255) NOT NULL,os_version varchar(255) NOT NULL,user_name varchar(255) NOT NULL,computer_name varchar(255) NOT NULL,processor_identifier varchar(255) NOT NULL,processor_architecture varchar(255) NOT NULL,number_of_processors INT NOT NULL,operators nvarchar(4096),PRIMARY KEY(id))")
	CheckErr(err)
	_, err = mysql.Exec("CREATE TABLE IF NOT EXISTS " + config.Tables.UserTable + " (id INT NOT NULL AUTO_INCREMENT, token varchar(12) NOT NULL, discord_id BIGINT NOT NULL, resources nvarchar(1024), ip_addresses nvarchar(1024), PRIMARY KEY(id))")
	CheckErr(err)
	_, err = mysql.Exec("CREATE TABLE IF NOT EXISTS " + config.Tables.ResourcesTable + " (id INT NOT NULL AUTO_INCREMENT, resource_name varchar(1024) NOT NULL, response_data nvarchar(8192) NOT NULL, channel_id varchar(18), PRIMARY KEY(id))")
	CheckErr(err)
}

func InitPreparedStatements() {
	stmt, err := mysql.Prepare("SELECT resources FROM " + config.Tables.UserTable + " WHERE token = ?")
	CheckErr(err)
	stmtSelectResourcesFromUserTable = stmt
	stmt, err = mysql.Prepare("INSERT INTO " + config.Tables.LogTable + " (token, resource, ip_address, os_name, os_arch, os_version, user_name, computer_name, processor_identifier, processor_architecture, number_of_processors, operators) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
	CheckErr(err)
	stmtInsertLog = stmt
	stmt, err = mysql.Prepare("SELECT response_data FROM " + config.Tables.ResourcesTable + " WHERE resource_name = ?")
	CheckErr(err)
	stmtSelectResponseData = stmt
}

func LogAuthentication(token string, data AuthenticationData) {
	bytes, err := json.Marshal(data.Operators)
	CheckErr(err)
	var numberOfProcessors int
	if len(data.NumberOfProcessors) > 0 {
		numberOfProcessors, err = strconv.Atoi(data.NumberOfProcessors)
		CheckErr(err)
	}
	_, err = stmtInsertLog.Exec(token, data.Resource, data.IPAddress, data.OsName, data.OsArch, data.OsVersion, data.UserName, data.ComputerName, data.ProcessorIdentifier, data.ProcessorArchitecture, numberOfProcessors, string(bytes))
	CheckErr(err)
}

func GetResources(token string) []string {
	var resourcesString string
	err := stmtSelectResourcesFromUserTable.QueryRow(token).Scan(&resourcesString)
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
