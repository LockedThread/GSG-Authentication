package main

import "fmt"

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
	NumberOfProcessors    string   `json:"numberOfProcessors"`
	Operators             []string `json:"operators"`
}

func (a AuthenticationData) ToString() {
	fmt.Printf("%+v\n", a)
}
