package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
)

func main() {

	// openssl req  -nodes -new -x509  -keyout server.key -out server.cert
	//This produces a cert with an unencrypted private key. Upload the cert to your connected app.

	const grantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"

	dat, err := ioutil.ReadFile("server.key")
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

	// Create the Claims
	claims := customClaims{
		//user
		jwt.StandardClaims{
			//	Issuer:
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
	fmt.Println(jwt)

	form := url.Values{}
	form.Set("grant_type", grantType)
	form.Set("assertion", jwt)

	req, err := http.NewRequest("POST", "https://login.salesforce.com/services/oauth2/token", strings.NewReader(form.Encode()))
	if err != nil {
		panic(err)
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	defer res.Body.Close()

	body, _ := ioutil.ReadAll(res.Body)

	fmt.Println(string(body))
}
