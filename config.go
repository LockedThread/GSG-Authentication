package main

import (
	"gopkg.in/yaml.v2"
	"io/ioutil"
)

type Config struct {
	Host     string `yaml:"host"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	DbName   string `yaml:"database-name"`
	Tables   struct {
		UserTable      string `yaml:"users"`
		ResourcesTable string `yaml:"resources"`
		LogTable       string `yaml:"logs"`
	}
}

func (c *Config) SetupConfig() *Config {
	yamlFile, err := ioutil.ReadFile("config.yml")
	CheckErr(err)
	err = yaml.Unmarshal(yamlFile, &c)
	CheckErr(err)
	return c
}
