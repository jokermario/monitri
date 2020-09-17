package accounts

import (
	"context"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	routing "github.com/go-ozzo/ozzo-routing/v2"
	"github.com/gomodule/redigo/redis"
	"github.com/jokermario/monitri/internal/entity"
	"github.com/jokermario/monitri/internal/errors"
	"net/http"
	"strings"
)

// Handler returns a JWT-based authentication middleware.
func Handler(AccessTokenVerificationKey, RefreshTokenVerificationKey string, service2 Service, conn redis.Conn) routing.Handler {
	return JWT(AccessTokenVerificationKey, RefreshTokenVerificationKey, service2, conn, JWTOptions{TokenHandler: handleToken})
}

// JWTTokenHandler represents a handler function that handles the parsed JWT token.
type JWTTokenHandler func(*routing.Context, Service, redis.Conn, *jwt.Token) error

// VerificationKeyHandler represents a handler function that gets a dynamic VerificationKey
type VerificationKeyHandler func(*routing.Context) string

// DefaultRealm is the default realm name for HTTP authentication. It is used by HTTP authentication based on
// Basic and Bearer.
var DefaultRealm = "API"

type JWTOptions struct {
	// auth realm. Defaults to "API".
	Realm string
	// the allowed signing method. This is required and should be the actual method that you use to create JWT token. It defaults to "HS256".
	SigningMethod string
	// a function that handles the parsed JWT token. Defaults to DefaultJWTTokenHandler, which stores the token in the routing context with the key "JWT".
	TokenHandler JWTTokenHandler
	// a function to get a dynamic VerificationKey
	GetVerificationKey VerificationKeyHandler
}

// DefaultJWTTokenHandler stores the parsed JWT token in the routing context with the key named "JWT".
func DefaultJWTTokenHandler(c *routing.Context, service Service, conn redis.Conn, token *jwt.Token) error {
	c.Set("JWT", token)
	return nil
}

// Handler returns a JWT-based authentication middleware.
func JWT(AccessTokenVerificationKey, RefreshTokenVerificationKey string,  service2 Service, conn redis.Conn, options ...JWTOptions) routing.Handler {
	var opt JWTOptions
	if len(options) > 0 {
		opt = options[0]
	}
	if opt.Realm == "" {
		opt.Realm = DefaultRealm
	}
	if opt.SigningMethod == "" {
		opt.SigningMethod = "HS256"
	}
	if opt.TokenHandler == nil {
		opt.TokenHandler = DefaultJWTTokenHandler
	}
	parser := &jwt.Parser{
		ValidMethods: []string{opt.SigningMethod},
	}

	return func(c *routing.Context) error {
		header := c.Request.Header.Get("Authorization")
		refHeader := c.Request.Header.Get("RefreshTokenAuth")
		message := ""
		if opt.GetVerificationKey != nil {
			AccessTokenVerificationKey = opt.GetVerificationKey(c)
		}
		if header != "" {
			if strings.HasPrefix(header, "Bearer ") {
				token, err := parser.Parse(header[7:], func(t *jwt.Token) (interface{}, error) { return []byte(AccessTokenVerificationKey), nil })
				if err == nil && token.Valid {
					err = opt.TokenHandler(c, service2, conn,token)
				}
				if err == nil {
					return nil
				}
				message = err.Error()
			}
		}

		if refHeader != "" {
			if strings.HasPrefix(refHeader, "Bearer ") {
				token, err := parser.Parse(refHeader[7:], func(t *jwt.Token) (interface{}, error) { return []byte(RefreshTokenVerificationKey), nil })
				if err == nil && token.Valid {
					err = opt.TokenHandler(c, service2, conn,token)
				}
				if err == nil {
					return nil
				}
				fmt.Println(err.Error())
				message = err.Error()
			}
		}
		c.Response.Header().Set("WWW-Authenticate", `Bearer realm="`+opt.Realm+`"`)
		if message != "" {
			return routing.NewHTTPError(http.StatusUnauthorized, message)
		}
		return routing.NewHTTPError(http.StatusUnauthorized)
	}
}

// handleToken stores the accounts identity in the request context so that it can be accessed elsewhere.
func handleToken(c *routing.Context, service2 Service, conn redis.Conn, token *jwt.Token) error {
	header := c.Request.Header.Get("Authorization")
	refHeader := c.Request.Header.Get("RefreshTokenAuth")

	if header != "" {
		//generate new access token, store it in redis and delete the old one
		val, _ := service2.checkAuthKeyIfExist(conn, token.Claims.(jwt.MapClaims)["accessUUID"].(string))
		if val == "" {
			return errors.Unauthorized("access token expired")
		}

		ctx := WithUser(
			c.Request.Context(), token.Claims.(jwt.MapClaims)["accessUUID"].(string),
			"",
			token.Claims.(jwt.MapClaims)["userId"].(string),
			token.Claims.(jwt.MapClaims)["email"].(string), token.Claims.(jwt.MapClaims)["phone"].(string))
		c.Request = c.Request.WithContext(ctx)
		return nil
	}
	if refHeader != "" {
		//generate new access token, store it in redis and delete the old one
		val, _ := service2.checkAuthKeyIfExist(conn, token.Claims.(jwt.MapClaims)["refreshUUID"].(string))
		if val == "" {
			return errors.Unauthorized("refresh token expired")
		}

		ctx := WithUser(
			c.Request.Context(), "",
			token.Claims.(jwt.MapClaims)["refreshUUID"].(string),
			token.Claims.(jwt.MapClaims)["userId"].(string),
			token.Claims.(jwt.MapClaims)["email"].(string), "")
		c.Request = c.Request.WithContext(ctx)
		return nil
	}
	return nil

}

type contextKey int

const (
	userKey contextKey = iota
)

// WithUser returns a context that contains the accounts identity from the given JWT.
func WithUser(ctx context.Context, accessUUID, refreshUUID, id, email, phone string) context.Context {
	if accessUUID != "" {
		return context.WithValue(ctx, userKey, entity.Accounts{AccessUUID: accessUUID, Id: id, Email: email, Phone: phone})
	}
	if refreshUUID != "" {
		return context.WithValue(ctx, userKey, entity.Accounts{RefreshUUID: refreshUUID, Id: id, Email: email, Phone: phone})
	}

	return nil
}

// CurrentAccount returns the accounts identity from the given context.
// Nil is returned if no accounts identity is found in the context.
func CurrentAccount(ctx context.Context) Identity {
	if account, ok := ctx.Value(userKey).(entity.Accounts); ok {
		return account
	}
	return nil
}

// MockAuthHandler creates a mock authentication middleware for testing purpose.
// If the request contains an Authorization header whose value is "TEST", then
// it considers the accounts is authenticated as "Tester" whose ID is "100".
// It fails the authentication otherwise.
func MockAuthHandler(c *routing.Context) error {
	if c.Request.Header.Get("Authorization") != "TEST" {
		return errors.Unauthorized("")
	}
	ctx := WithUser(c.Request.Context(), "", "", "100", "Tester", "")
	c.Request = c.Request.WithContext(ctx)
	return nil
}

// MockAuthHeader returns an HTTP header that can pass the authentication check by MockAuthHandler.
func MockAuthHeader() http.Header {
	header := http.Header{}
	header.Add("Authorization", "TEST")
	return header
}
