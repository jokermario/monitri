package accounts

import (
	"context"
	"github.com/dgrijalva/jwt-go"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
	"github.com/gomodule/redigo/redis"
	"github.com/jokermario/monitri/internal/email"
	"github.com/jokermario/monitri/internal/entity"
	"github.com/jokermario/monitri/internal/errors"
	"github.com/jokermario/monitri/pkg/log"
	"golang.org/x/crypto/bcrypt"
	"regexp"
	"strings"
	"time"
)

type Service interface {
	GetById(ctx context.Context, id string) (Account, error)
	GetAccountByEmail(ctx context.Context, email string) (Account, error)
	Count(ctx context.Context) (int, error)
	UpdateProfile(ctx context.Context, id string, req UpdateAccountRequest) (Account, error)
	DeleteById(ctx context.Context, id string) error
	GetAccounts(ctx context.Context, offset, limit int) ([]Account, error)
	Login(ctx context.Context, req LoginRequest) (*TokenDetails, error)
	CreateAccount(ctx context.Context, req CreateAccountsRequest) (*TokenDetails, error)
	storeAuthTokens(conn redis.Conn, email string, td *TokenDetails) error
	//GetCurrentUser(ctx context.Context) string
}

// Identity represents an authenticated accounts identity.
type Identity interface {
	GetID() string
	GetEmail() string
	GetPhone() string
}

type service struct {
	repo                   Repository
	logger                 log.Logger
	emailService           email.Service
	AccessTokenSigningKey  string
	RefreshTokenSigningKey string
	AccessTokenExpiration  int
	RefreshTokenExpiration int
}

type Account struct {
	entity.Accounts
}

type TokenDetails struct {
	AccessToken string
	RefreshToken string
	AccessUuid   string
	RefreshUuid  string
	AtExpires    int64
	RtExpires    int64
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type CreateAccountsRequest struct {
	Email    string `json:"email"`
	Phone    string `json:"phone"`
	Password string `json:"password"`
}

func (lr LoginRequest) validate() error {
	return validation.ValidateStruct(&lr,
		validation.Field(&lr.Email, validation.Required, is.Email),
		validation.Field(&lr.Password, validation.Required))
}

func (car CreateAccountsRequest) validate() error {
	return validation.ValidateStruct(&car,
		validation.Field(&car.Email, validation.Required, is.Email),
		validation.Field(&car.Phone, validation.Required),
		validation.Field(&car.Password, validation.Required, validation.Length(8, 0)))
}

type UpdateAccountRequest struct {
	Firstname        string `json:"firstname"`
	Middlename       string `json:"middlename"`
	Lastname         string `json:"lastname"`
	Dob              string `json:"dob"`
	Password         string `json:"password"`
	Address          string `json:"address"`
	Bankname         string `json:"bankname"`
	BankAccountNo    string `json:"bank_account_no"`
	ConfirmedEmail   int    `json:"confirmed_email"`
	ConfirmedPhone   int    `json:"confirmed_phone"`
	Managed          int    `json:"managed"`
	AccountManagerId string `json:"account_manager_id"`
}

func (uar UpdateAccountRequest) validate() error {
	return validation.ValidateStruct(&uar,
		validation.Field(&uar.Firstname, validation.Match(regexp.MustCompile("^[a-zA-Z]+$"))),
		validation.Field(&uar.Middlename, validation.Match(regexp.MustCompile("^[a-zA-Z]+$"))),
		validation.Field(&uar.Lastname, validation.Match(regexp.MustCompile("^[a-zA-Z]+$"))),
		validation.Field(&uar.Dob, validation.Match(regexp.MustCompile("^\\d{4}\\-(0[1-9]|1[012])\\-(0[1-9]|[12][0-9]|3[01])$"))),
		validation.Field(&uar.Password, validation.Length(8, 0)),
		validation.Field(&uar.Address, is.Alphanumeric),
		validation.Field(&uar.Bankname, validation.Match(regexp.MustCompile("^[a-zA-Z]+$"))),
		validation.Field(&uar.BankAccountNo, validation.Match(regexp.MustCompile("^[0-9]+$"))),
		validation.Field(&uar.ConfirmedEmail, validation.Length(1, 1), is.Int),
		validation.Field(&uar.ConfirmedPhone, validation.Length(1, 1), is.Int),
		validation.Field(&uar.Managed, validation.Length(1, 1), is.Int),
		validation.Field(&uar.AccountManagerId, validation.Length(36, 0)))
}

func NewService(repo Repository, logger log.Logger, email email.Service, AccessTokenSigningKey, RefreshTokenSigningKey string, AccessTokenExpiration, RefreshTokenExpiration int) Service {
	return service{repo, logger, email, AccessTokenSigningKey, RefreshTokenSigningKey, AccessTokenExpiration, RefreshTokenExpiration}
}

func (s service) GetById(ctx context.Context, id string) (Account, error) {
	account, err := s.repo.GetById(ctx, id)
	if err != nil {
		return Account{}, err
	}
	return Account{account}, err
}

func (s service) GetAccountByEmail(ctx context.Context, email string) (Account, error) {
	account, err := s.repo.GetAccountByEmail(ctx, email)
	if err != nil {
		return Account{}, err
	}
	return Account{account}, err
}

func (s service) Count(ctx context.Context) (int, error) {
	return s.repo.Count(ctx)
}

func (s service) UpdateProfile(ctx context.Context, id string, req UpdateAccountRequest) (Account, error) {
	if err := req.validate(); err != nil {
		return Account{}, err
	}
	account, err := s.GetById(ctx, id)
	if err != nil {
		return Account{}, err
	}
	account.Firstname = strings.TrimSpace(req.Firstname)
	account.Middlename = strings.TrimSpace(req.Middlename)
	account.Lastname = strings.TrimSpace(req.Lastname)
	account.Dob = strings.TrimSpace(req.Dob)
	account.Address = strings.TrimSpace(req.Address)
	account.UpdatedAt = time.Now()

	if err := s.repo.Update(ctx, account.Accounts); err != nil {
		return Account{}, err
	}
	return account, nil
}

func (s service) DeleteById(ctx context.Context, id string) error {
	_, err := s.GetById(ctx, id)
	if err != nil {
		return err
	}
	if err := s.repo.Delete(ctx, id); err != nil {
		return err
	}
	return nil
}

//func (s service) GenerateEmailVerificationToken(ctx context.Context, )

func (s service) GetAccounts(ctx context.Context, offset, limit int) ([]Account, error) {
	accounts, err := s.repo.GetAccounts(ctx, offset, limit)
	if err != nil {
		return nil, err
	}
	result := []Account{}
	for _, account := range accounts {
		result = append(result, Account{account})
	}
	return result, nil
}

// Login authenticates a accounts and generates a JWT token if authentication succeeds.
// Otherwise, an error is returned.
func (s service) Login(ctx context.Context, req LoginRequest) (*TokenDetails, error) {
	if err := req.validate(); err != nil {
		return nil, err
	}
	if identity := s.authenticate(ctx, req.Email, req.Password); identity != nil {
		return s.generateTokens(identity)
	}
	return nil, errors.Unauthorized("")
}

// authenticate authenticates a accounts using username and password.
// If username and password are correct, an identity is returned. Otherwise, nil is returned.
func (s service) authenticate(ctx context.Context, email, password string) Identity {
	logger := s.logger.With(ctx, "accounts", email)

	account, err := s.repo.GetAccountByEmail(ctx, email)
	if err != nil {
		logger.Errorf("an error occurred while trying to get the account with the email: %s\n The error is: %s", email, err)
		return nil
	}
	if err := bcrypt.CompareHashAndPassword([]byte(account.Password), []byte(password)); err != nil {
		switch err {
		case bcrypt.ErrMismatchedHashAndPassword:
			logger.Errorf("the password is does not exist")
			return nil
		default:
			logger.Errorf("an error occurred while tyring to compare bcrypt password with input password")
			return nil
		}
	}
	logger.Infof("authentication successful. Email: %s", email)
	return account
}

func (s service) getAccount(ctx context.Context, id string) Identity {
	accountInfo, err := s.repo.GetIdEmailPhone(ctx, id)
	if err != nil {
		return nil
	}
	return entity.Accounts{Id: accountInfo.Id, Email: accountInfo.Email, Phone: accountInfo.Phone}
}

func (s service) CreateAccount(ctx context.Context, req CreateAccountsRequest) (*TokenDetails, error) {
	logger := s.logger.With(ctx, "account", req.Email)
	if err := req.validate(); err != nil {
		return nil, err
	}
	id := entity.GenerateID()
	hashedPass, _ := bcrypt.GenerateFromPassword([]byte(req.Password), 12)

	err := s.repo.Create(ctx, entity.Accounts{
		Id:       strings.TrimSpace(id),
		Email:    strings.TrimSpace(req.Email),
		Phone:    req.Phone,
		Password: string(hashedPass),
	})
	if err != nil {
		return nil, err
	}
	resp, emailErr := s.emailService.SendEmail("healer800@gmail.com", "flexikiid007@gmail.com", "Testing this email sending from Golang", "plain text", "<p><strong>The Message!!</strong>Not bold</p>")
	if emailErr != nil {
		s.logger.Errorf("an error occurred while trying to send email.\nThe error: %s\nResponseBody: %s\nResponseCode: %s", err, resp.Body, resp.StatusCode)
		return nil, emailErr
	}

	logger.Infof("account created successfully. Email sending response body: %s, response code: %s", resp.Body, resp.StatusCode)
	return s.generateTokens(s.getAccount(ctx, id))
}

func (s service) generateTokens(identity Identity) (*TokenDetails, error) {
	td := &TokenDetails{}
	var accerr error
	var referr error
	td.AtExpires = time.Now().Add(time.Duration(s.AccessTokenExpiration) * time.Hour).Unix()
	td.RtExpires = time.Now().Add(time.Duration(s.RefreshTokenExpiration) * time.Hour).Unix()
	td.AccessUuid = entity.GenerateID()
	td.RefreshUuid = entity.GenerateID()

	td.AccessToken, accerr = s.generateAccessToken(identity, td.AccessUuid, td.AtExpires)
	if accerr != nil {
		return nil, accerr
	}
	td.RefreshToken, referr = s.generateRefreshToken(identity, td.RefreshUuid, td.RtExpires)
	if referr != nil {
		return nil, referr
	}

	log.New().Infof("here")
	return td, nil
}

// generateAccessToken generates a JWT that encodes an identity.
func (s service) generateAccessToken(identity Identity, tokenUUID string, expiryTime int64) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"authorized": true,
		"accessUUID": tokenUUID,
		"userId":     identity.GetID(),
		"email":      identity.GetEmail(),
		"phone":      identity.GetPhone(),
		"exp":        expiryTime,
	}).SignedString([]byte(s.AccessTokenSigningKey))
}

// generateRefreshToken generates a JWT that encodes an identity used to regenerate an access token.
func (s service) generateRefreshToken(identity Identity, tokenUUID string, expiryTime int64) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"refreshUUID": tokenUUID,
		"userId":      identity.GetID(),
		"email":       identity.GetEmail(),
		"phone":       identity.GetPhone(),
		"exp":         expiryTime,
	}).SignedString([]byte(s.RefreshTokenSigningKey))
}

//redis
func (s service) storeAuthTokens(conn redis.Conn, email string, td *TokenDetails) error {
	at := time.Unix(td.AtExpires, 0) //converting unix to UTC(to time object)
	rt := time.Unix(td.RtExpires, 0)
	log.New().Infof("rt = %s", rt)
	now := time.Now()
	log.New().Infof("now = %s", now)

	errAccess := s.repo.SetRedisKey(conn, int64(at.Sub(now).Seconds()), email, td.AccessToken); if errAccess != nil {
		return errAccess
	}
	errRefresh := s.repo.SetRedisKey(conn, int64(rt.Sub(now).Seconds()), email, td.RefreshToken); if errRefresh != nil {
		return errRefresh
	}
	log.New().Infof("sub = %s", int64(rt.Sub(now).Seconds()))
	return nil
}