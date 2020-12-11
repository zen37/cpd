package main

import (
	"fmt"
	"io/ioutil"
	"log"

	"github.com/zen37/cpd/salesforce"
	"gopkg.in/yaml.v2"
)

type yamlCfg struct {
	Credentials struct {
		ClientID     string `yaml:"client_id"`
		ClientSecret string `yaml:"client_secret"`
		Username     string `yaml:"username"`
		Password     string `yaml:"password"`
	}
	Endpoints struct {
		TokenURL string `yaml:"token_url"`
	}
}

func main() {
	cfg := yamlCfg{}

	//yamlFile, err := ioutil.ReadFile("../.config.yaml")
	yamlFile, err := ioutil.ReadFile("./salesforce/.config.yaml")
	if err != nil { // 	log.Printf("File cannot be read - %v ", err)
		log.Fatal(err)
	}

	err = yaml.Unmarshal(yamlFile, &cfg)
	if err != nil {
		log.Fatal(err)
	}

	sfClient := salesforce.New(salesforce.Config{
		Credentials: salesforce.Credentials{
			ClientID:     cfg.Credentials.ClientID,
			ClientSecret: cfg.Credentials.ClientSecret,
			Username:     cfg.Credentials.Username,
			Password:     cfg.Credentials.Password,
		},
	})

	token, err := sfClient.GetToken()
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(token)
}
