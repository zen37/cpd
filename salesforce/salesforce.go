package salesforce

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/jws"
)

type Result struct {
	AccessToken string `json:"access_token"`
}

type (
	Auth struct {
		AuthType    string
		Credentials Credentials
		Consumer    Consumer
		Endpoints   Endpoints
	}
	Consumer struct {
		Key    string
		Secret string
		Scopes []string
	}

	Credentials struct {
		Username string
		Password string
	}

	Endpoints struct {
		RedirectURL string
		AuthURL     string
		TokenURL    string
	}
	Client struct {
		auth   Auth
		client *http.Client
		oauth2 oauth2.Config
	}
)

var (
	cfg   oauth2.Config
	token *oauth2.Token
)

//New returns client
func New(auth Auth) (*Client, error) {

	var c Client

	switch auth.AuthType {

	case "password":

		err := authPassword(&c, auth)
		if err != nil {
			return nil, err
		}

	case "code":
		err := authCode(&c, auth)
		if err != nil {
			return nil, err
		}

	case "jwt":

		err := authJWT(&c, auth)
		if err != nil {
			return nil, err
		}

	default:
		return nil, errors.New("unknown authorization type, it should be either: password, code")
	}

	c.auth.AuthType = auth.AuthType

	return &c, nil

}

func authJWT(c *Client, auth Auth) error {

	c.client = &http.Client{}

	c.auth.Consumer.Key = auth.Consumer.Key
	c.auth.Consumer.Secret = auth.Consumer.Secret

	c.auth.Endpoints.TokenURL = auth.Endpoints.TokenURL

	return nil
}

func authPassword(c *Client, auth Auth) error {

	if auth.Credentials.Password == "" {
		if auth.Credentials.Password = os.Getenv("SF_PASSWORD"); auth.Credentials.Password == "" {
			return errors.New("password not provided either as an env variable SF_PASSWORD or in config file")
		}
	}
	if auth.Credentials.Username == "" {
		if auth.Credentials.Username = os.Getenv("SF_USERNAME"); auth.Credentials.Username == "" {
			return errors.New("username not provided either as an env variable SF_USERNAME or in config file")
		}
	}
	c.client = &http.Client{}

	c.auth.Credentials.Username = auth.Credentials.Username
	c.auth.Credentials.Password = auth.Credentials.Password

	c.auth.Consumer.Key = auth.Consumer.Key
	c.auth.Consumer.Secret = auth.Consumer.Secret

	c.auth.Endpoints.TokenURL = auth.Endpoints.TokenURL

	return nil
}

func authCode(c *Client, auth Auth) error {

	cfg = oauth2.Config{
		ClientID:     auth.Consumer.Key,
		ClientSecret: auth.Consumer.Secret,
		Scopes:       auth.Consumer.Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  auth.Endpoints.AuthURL,
			TokenURL: auth.Endpoints.TokenURL,
		},
		RedirectURL: auth.Endpoints.RedirectURL,
	}

	return nil

}

//GetToken ....
func (c *Client) GetToken() (*Result, error) {

	switch c.auth.AuthType {

	case "password":
		r, err := c.getTokenPassword()
		if err != nil {
			return nil, err
		}
		return r, nil

	case "code":
		r, err := getTokenCode()
		if err != nil {
			return nil, err
		}
		return r, nil

	case "jwt":
		r, err := c.getTokenJWT()
		if err != nil {
			return nil, err
		}
		return r, nil

	default:
		return nil, nil
	}

}

func home(w http.ResponseWriter, r *http.Request) {
	fmt.Println("homepage hit!")
	u := cfg.AuthCodeURL("my_random_state")
	http.Redirect(w, r, u, http.StatusFound)
}

func authorize(w http.ResponseWriter, r *http.Request) {
	fmt.Println("oauth2 page hit!")
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	state := r.Form.Get("state")
	if state != "my_random_state" {
		http.Error(w, "State invalid", http.StatusBadRequest)
		return
	}

	code := r.Form.Get("code")
	if code == "" {
		http.Error(w, "Code not found", http.StatusBadRequest)
		return
	}

	token, err := cfg.Exchange(context.Background(), code)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Printf("%+v\n", token)
}

func getTokenCode() (*Result, error) {

	var r *Result

	//ctx := context.Background()'

	http.HandleFunc("/", home)
	http.HandleFunc("/oauth2", authorize)

	// We start up our Client on port 9094
	log.Println("Client is running at 9094 port.")
	log.Fatal(http.ListenAndServe(":9094", nil))

	//fmt.Println(tok.AccessToken)
	//c.client = cfg.Client(ctx, token)

	r.AccessToken = token.AccessToken

	return r, nil

}

func (c *Client) getTokenPassword() (*Result, error) {

	var r Result

	form := &url.Values{}

	form.Set("client_id", c.auth.Consumer.Key)
	form.Set("client_secret", c.auth.Consumer.Secret)
	form.Set("username", c.auth.Credentials.Username)
	form.Set("password", c.auth.Credentials.Password)
	form.Set("grant_type", "password")

	//fmt.Println(c.auth)

	request, err := http.NewRequest("POST", c.auth.Endpoints.TokenURL, strings.NewReader(form.Encode())) // URL-encoded payload
	if err != nil {
		return nil, err
	}

	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	response, err := c.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		return nil, errors.New(response.Status)
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	//fmt.Println(string(body))
	err = json.Unmarshal(body, &r)
	if err != nil {
		return nil, err
	}

	return &r, nil
}

func (c *Client) getTokenJWT() (*Result, error) {

	//https://help.salesforce.com/articleView?id=remoteaccess_oauth_jwt_flow.htm&type=5
	//https://github.com/golang/oauth2/blob/master/jwt/jwt.go

	var (
		grantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"
		header    = &jws.Header{Algorithm: "RS256", Typ: "JWT"}
		//defaultHeader    = &jws.Header{Algorithm: "RS256", Typ: "JWT"}
	)

	pkFile, err := ioutil.ReadFile("salesforce/key2.pem")
	if err != nil {
		log.Fatal(err)
	}

	pk, err := parseRsaPrivateKeyFromPemStr(string(pkFile))
	if err != nil {
		log.Fatal(err)
	}
	//fmt.Println(pk)

	claimSet := &jws.ClaimSet{
		Iss:   c.auth.Consumer.Key + "." + c.auth.Consumer.Secret,
		Sub:   c.auth.Credentials.Username,
		Scope: strings.Join(c.auth.Consumer.Scopes, " "),
		Aud:   c.auth.Endpoints.TokenURL,
	}

	h := *header
	//h.KeyID = //https://github.com/golang/oauth2/blob/master/jwt/jwt.go

	jwt, err := jws.Encode(&h, claimSet, pk)
	if err != nil {
		return nil, err
	}
	//	fmt.Println(claimSet)

	form := url.Values{}
	form.Set("grant_type", grantType)
	form.Set("assertion", jwt) //assertion	The assertion is the entire JWT value.

	resp, err := c.client.PostForm(c.auth.Endpoints.TokenURL, form)
	if err != nil {
		return nil, err //fmt.Errorf("oauth2: cannot fetch token: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, errors.New(resp.Status)
	}

	body, err := ioutil.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err //fmt.Errorf("oauth2: cannot fetch token: %v", err)
	}

	var r *Result

	err = json.Unmarshal(body, &r)
	if err != nil {
		return nil, err
	}

	fmt.Println("r = ", r)

	return r, nil

	/*
		claims := jwt.MapClaims{}

		//claims["iss"] = "3MVG99OxTyEMCQ3gNp2PjkqeZKxnmAiG1xV4oHh9AKL_rSK.BoSVPGZHQukXnVjzRgSuQqGn75NL7yfkQcyy7"
		claims["iss"] = "cpd"
		claims["sub"] = c.auth.Credentials.Username
		claims["aud"] = c.auth.Endpoints.TokenURL
		claims["exp"] = time.Now().Add(time.Minute * 30).Unix()
	*/
}

func parseRsaPrivateKeyFromPemStr(privPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return priv, nil
}
