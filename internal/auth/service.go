package auth
//
//import (
//	"context"
//	"github.com/dgrijalva/jwt-go"
//	validation "github.com/go-ozzo/ozzo-validation/v4"
//	"github.com/go-ozzo/ozzo-validation/v4/is"
//	"github.com/jokermario/monitri/internal/accounts"
//	"github.com/jokermario/monitri/internal/email"
//	"github.com/jokermario/monitri/internal/entity"
//	"github.com/jokermario/monitri/internal/errors"
//	"github.com/jokermario/monitri/pkg/log"
//	"golang.org/x/crypto/bcrypt"
//	"strings"
//	"time"
//)
//
//// Service encapsulates the authentication logic.
//type Service interface {
//	// authenticate authenticates a accounts using username and password.
//	// It returns a JWT token if authentication succeeds. Otherwise, an error is returned.
//	login(ctx context.Context, req LoginRequest) (string, error)
//	createAccount(ctx context.Context, req CreateAccountsRequest) (string, error)
//}
//
//
//type service struct {
//	logger          log.Logger
//}
//
//// NewService creates a new authentication service.
//func NewService(logger log.Logger) Service {
//	return service{signingKey, tokenExpiration, logger}
//}
