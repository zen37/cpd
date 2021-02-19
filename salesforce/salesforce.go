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
	"time"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/oauth2"
)

type AuthType string //int

const (
	authTypePassword AuthType = "password" //AuthType = iota
	authTypeCode     AuthType = "code"
	authTypeJWT      AuthType = "jwt"
)

type Result struct {
	AccessToken string `json:"access_token"`
	Instance    string `json:"instance_url"`
}

type (
	Auth struct {
		AuthType    AuthType //  string
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

	case authTypePassword:
		err := authPassword(&c, auth)
		if err != nil {
			return nil, err
		}

	case authTypeCode:
		//case "code":
		err := authCode(&c, auth)
		if err != nil {
			return nil, err
		}

	//case "jwt":
	case authTypeJWT:
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
	c.auth.Credentials.Username = auth.Credentials.Username
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

	//fmt.Println("c.auth.AuthType:", c.auth.AuthType)

	switch c.auth.AuthType {

	case authTypePassword:
		r, err := c.getTokenPassword()
		if err != nil {
			return nil, err
		}
		return r, nil

	case authTypeCode:
		r, err := getTokenCode()
		if err != nil {
			return nil, err
		}
		return r, nil

	case authTypeJWT:
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

	var r *Result

	form := &url.Values{}

	form.Set("client_id", c.auth.Consumer.Key)
	form.Set("client_secret", c.auth.Consumer.Secret)
	form.Set("username", c.auth.Credentials.Username)
	form.Set("password", c.auth.Credentials.Password)
	form.Set("grant_type", "password")

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

	//	fmt.Println(string(body))
	err = json.Unmarshal(body, &r)
	if err != nil {
		return nil, err
	}

	return r, nil
}

func (c *Client) getTokenJWT() (*Result, error) {

	// openssl req  -nodes -new -x509  -keyout server.key -out server.cert
	//This produces a cert with an unencrypted private key. Upload the cert to your connected app.
	dat, err := ioutil.ReadFile("salesforce/server.key")
	if err != nil {
		panic(err)
	}

	signKey, err := jwt.ParseRSAPrivateKeyFromPEM(dat)
	if err != nil {
		panic(err)
	}

	now := time.Now().UTC()
	exp := now.Add(24 * time.Hour)

	// create a signer for rsa 256
	t := jwt.New(jwt.GetSigningMethod("RS256"))

	type customClaims struct {
		Sub string `json:"sub"`
		jwt.StandardClaims
	}

	claims := customClaims{
		c.auth.Credentials.Username,
		jwt.StandardClaims{
			Issuer:    c.auth.Consumer.Key,
			Audience:  "https://login.salesforce.com",
			NotBefore: now.Unix(),
			ExpiresAt: exp.Unix(),
			IssuedAt:  now.Unix(),
		},
	}

	t.Claims = claims
	jwt, err := t.SignedString(signKey)
	if err != nil {
		panic(err)
	}

	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	form.Set("assertion", jwt)

	req, err := http.NewRequest("POST", c.auth.Endpoints.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		panic(err)
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, errors.New(res.Status)
	}

	//body, _ := ioutil.ReadAll(res.Body)
	body, err := ioutil.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, err
	}

	var r Result

	err = json.Unmarshal(body, &r)
	if err != nil {
		return nil, err
	}

	//	fmt.Println(string(body))
	return &r, nil

}

func parseRsaPrivateKeyFromPemStr(privPEM string) (*rsa.PrivateKey, error) {

	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	//priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)

	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)

	if err != nil {
		return nil, err
	}

	p := priv.(*rsa.PrivateKey)
	return p, nil
}

/*
func (auth AuthType) String() string {
	types := [...]string{
		"password",
		"code",
		"jwt",
	}
	return types[auth]
}
*/
