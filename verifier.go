package auth

import (
	"crypto/rsa"
	"errors"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
)

var(
	ErrExpiredToken = errors.New("expired jwt needs refresh")
)

type Authenticator struct {
	publicKey  *rsa.PublicKey
}

func NewAuthenticator(publicKeyPath string) (*Authenticator, error) {
	publicKeyFile, err := ioutil.ReadFile(publicKeyPath)
	if err != nil {
		return nil, err
	}
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyFile)
	if err != nil {
		return nil, err
	}
	return &Authenticator{ publicKey: publicKey }, nil
}

func (auth *Authenticator) Authenticate(r *http.Request) (user User, err error) {
	token, err := getTokenFromRequest(r)
	if err != nil {
		return User{}, err
	}

	return auth.authenticate(token)
}

func (auth *Authenticator) authenticate(token string) (User, error) {
	var c claims
	_, err := jwt.ParseWithClaims(token, &c, auth.publicKeyFunc)
	if err != nil {
		v, ok := err.(*jwt.ValidationError)
		if ok && v.Errors == jwt.ValidationErrorExpired {
			err = ErrExpiredToken
		}
	}
	return c.User, err
}

func (auth *Authenticator) publicKeyFunc(_ *jwt.Token) (interface{}, error) {
	return auth.publicKey, nil
}

func getTokenFromRequest(r *http.Request) (string, error) {
	value := r.Header.Get("Authorization")
	s := strings.Split(value, "Bearer")
	if len(s) != 2 {
		return "", errors.New("authorization header is not of the form: Bearer <token>")
	}

	return strings.TrimSpace(s[1]), nil
}
