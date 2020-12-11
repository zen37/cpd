package salesforce

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/oauth2"
)

type (
	Config struct {
		Credentials Credentials
		Endpoints   Endpoints
	}

	Credentials struct {
		ClientID     string
		ClientSecret string
		Username     string
		Password     string
	}

	Endpoints struct {
		TokenURL string
	}

	Client struct {
		cfg    Config
		client *http.Client
		oauth2 oauth2.Config
	}
)

const DefaultURL = "https://login.salesforce.com/services/oauth2/token"

func New(cfg Config) *Client {
	var c Client
	if cfg.Endpoints.TokenURL == "" {
		cfg.Endpoints.TokenURL = DefaultURL
	}

	c.cfg = cfg
	c.client = &http.Client{}

	c.oauth2 = &oauth2.Config{
		ClientID:     cfg.Credentials.ClientID,
		ClientSecret: cfg.Credentials.ClientSecret,
		RedirectURL:  "https://login.salesforce.com/services/oauth2/success",
		Scopes:       []string{"api"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://login.salesforce.com/services/oauth2/authorize",
			TokenURL: "https://login.salesforce.com/services/oauth2/token",
		},
	}

	return &c
}

type Result struct {
	Token       string `json:"access_token"`
	InstanceURL string `json:"instance_url"`
}

// func (s *Saleforce) GetSoemthing {
// 	s.Whatever
// }

func (c *Client) GetToken() (*Result, error) {

	fmt.Println(c.cfg)

	// endpoint := cfg.Endpoints.TokenURL

	// //fmt.Println(cfg)

	form := &url.Values{}

	form.Set("client_id", c.cfg.Credentials.ClientID)
	form.Set("client_secret", c.cfg.Credentials.ClientSecret)
	form.Set("username", c.cfg.Credentials.Username)
	form.Set("password", c.cfg.Credentials.Password)
	form.Set("grant_type", "password") //client_credentials //authorization_code

	//data := "client_id=...&client_secret=..."

	request, err := http.NewRequest("POST", c.cfg.Endpoints.TokenURL, strings.NewReader(form.Encode())) // URL-encoded payload
	if err != nil {
		return nil, err
	}
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	response, err := c.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	log.Println(response.Status)

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	var r Result
	err = json.Unmarshal(body, &r)
	if err != nil {
		return nil, err
	}

	return &r, nil
}
