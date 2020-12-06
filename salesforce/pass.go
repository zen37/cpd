package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"

	"gopkg.in/yaml.v2"
)

// Local todocheck configuration struct definition
type config struct {
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
	Username     string `yaml:"username"`
	Password     string `yaml:"password"`
}

type result struct {
	Token       string `json:"access_token"`
	InstanceURL string `json:"instance_url"`
}

func main() {

	cfg := config{}

	yamlFile, err := ioutil.ReadFile(".config.yaml")
	if err != nil {
		log.Printf("yamlFile.Get err   #%v ", err)
	}
	err = yaml.Unmarshal(yamlFile, &cfg)
	if err != nil {
		log.Fatal(err)
	}

	//fmt.Println(cfg)

	endpoint := "https://login.salesforce.com/services/oauth2/token"

	form := &url.Values{}

	form.Set("client_id", cfg.ClientID)
	form.Set("client_secret", cfg.ClientSecret)
	form.Set("username", cfg.Username)
	form.Set("password", cfg.Password)

	form.Set("grant_type", "password") //client_credentials //authorization_code

	//data := "client_id=...&client_secret=..."

	request, err := http.NewRequest("POST", endpoint, strings.NewReader(form.Encode())) // URL-encoded payload
	//r, err := http.NewRequest("POST", endpoint, strings.NewReader(data)
	if err != nil {
		log.Fatal(err)
	}
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		log.Fatal(err)
	}
	defer response.Body.Close()
	//	log.Println(response.Status)

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatal(err)
	}
	//	log.Println(string(body))

	var r result
	err = json.Unmarshal(body, &r)
	if err != nil {
		log.Fatal(err)
	}

	// fmt.Println(r)
	fmt.Printf("access token is %v\n", r.Token)
}
