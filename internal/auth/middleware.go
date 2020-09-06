package auth
//
//import (
//	"context"
//	"github.com/dgrijalva/jwt-go"
//	routing "github.com/go-ozzo/ozzo-routing/v2"
//	"github.com/go-ozzo/ozzo-routing/v2/auth"
//	"github.com/jokermario/monitri/internal/entity"
//	"github.com/jokermario/monitri/internal/errors"
//	"net/http"
//)
//
//// Handler returns a JWT-based authentication middleware.
//func Handler(verificationKey string) routing.Handler {
//	return auth.JWT(verificationKey, auth.JWTOptions{TokenHandler: handleToken})
//}
//
//// handleToken stores the accounts identity in the request context so that it can be accessed elsewhere.
//func handleToken(c *routing.Context, token *jwt.Token) error {
//	ctx := WithUser(
//		c.Request.Context(),
//		token.Claims.(jwt.MapClaims)["id"].(string),
//		token.Claims.(jwt.MapClaims)["email"].(string),
//		token.Claims.(jwt.MapClaims)["phone"].(string),
//	)
//	c.Request = c.Request.WithContext(ctx)
//	//fmt.Printf("the id %s\n. the email %s\n. The phone %s\n.", token.Claims.(jwt.MapClaims)["id"].(string), token.Claims.(jwt.MapClaims)["email"].(string),token.Claims.(jwt.MapClaims)["phone"].(string))
//	return nil
//}
//
//type contextKey int
//
//const (
//	userKey contextKey = iota
//)
//
//// WithUser returns a context that contains the accounts identity from the given JWT.
//func WithUser(ctx context.Context, id, email, phone string) context.Context {
//	return context.WithValue(ctx, userKey, entity.Accounts{Id: id, Email: email, Phone: phone})
//}
//
//// CurrentAccount returns the accounts identity from the given context.
//// Nil is returned if no accounts identity is found in the context.
//func CurrentAccount(ctx context.Context) Identity {
//	if account, ok := ctx.Value(userKey).(entity.Accounts); ok {
//		return account
//	}
//	return nil
//}
//
//// MockAuthHandler creates a mock authentication middleware for testing purpose.
//// If the request contains an Authorization header whose value is "TEST", then
//// it considers the accounts is authenticated as "Tester" whose ID is "100".
//// It fails the authentication otherwise.
//func MockAuthHandler(c *routing.Context) error {
//	if c.Request.Header.Get("Authorization") != "TEST" {
//		return errors.Unauthorized("")
//	}
//	ctx := WithUser(c.Request.Context(), "100", "Tester", "")
//	c.Request = c.Request.WithContext(ctx)
//	return nil
//}
//
//// MockAuthHeader returns an HTTP header that can pass the authentication check by MockAuthHandler.
//func MockAuthHeader() http.Header {
//	header := http.Header{}
//	header.Add("Authorization", "TEST")
//	return header
//}
