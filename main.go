package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/zen37/cpd/salesforce"
	"gopkg.in/yaml.v2"
)

type yamlCfg struct {
	AuthType string `yaml:"auth_type"`
	Consumer struct {
		Key    string   `yaml:"client_id"`
		Secret string   `yaml:"client_secret"`
		Scopes []string `yaml:"scopes"`
	}
	Credentials struct {
		Username string `yaml:"username"`
		Password string `yaml:"password"`
	}
	Endpoints struct {
		RedirectURL string `yaml:"redirect_url"`
		AuthURL     string `yaml:"auth_url"`
		TokenURL    string `yaml:"token_url"`
	}
}

func main() {

	cfg := yamlCfg{}

	yamlFile, err := ioutil.ReadFile("configs/.salesforce.yaml")
	if err != nil {
		log.Fatal(err)
	}

	err = yaml.Unmarshal(yamlFile, &cfg)
	if err != nil {
		log.Fatal(err)
	}

	sfClient, err := salesforce.New(salesforce.Auth{
		AuthType: cfg.AuthType,
		Consumer: salesforce.Consumer{
			Key:    cfg.Consumer.Key,
			Secret: cfg.Consumer.Secret,
			Scopes: cfg.Consumer.Scopes,
		},
		Credentials: salesforce.Credentials{
			Username: cfg.Credentials.Username,
			Password: cfg.Credentials.Password,
		},
		Endpoints: salesforce.Endpoints{
			RedirectURL: cfg.Endpoints.RedirectURL,
			AuthURL:     cfg.Endpoints.AuthURL,
			TokenURL:    cfg.Endpoints.TokenURL,
		},
	})
	if err != nil {
		log.Fatalln(err)
	}

	//	fmt.Println(sfClient)

	token, err := sfClient.GetToken()
	if err != nil {
		log.Fatalln(err)
	}
	//fmt.Println("token=", token)
	//fmt.Println()

	//api := "/services/data/v51.0/limits/"
	//	api := "/services/data/v51.0/sobjects/Account/quickActions"
	api := "/services/data/v51.0/sobjects/Account"

	limits := token.Instance + api

	req, err := http.NewRequest("GET", limits, nil)
	if err != nil {
		log.Fatalln(err)
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalln(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Fatalln("StatusCode=", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(string(body))

}
