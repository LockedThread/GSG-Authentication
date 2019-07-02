package main

type User struct {
	ID        int      `json:"ID"`
	Name      string   `json:"Name"`
	Resources []string `json:"Resources"`
}
