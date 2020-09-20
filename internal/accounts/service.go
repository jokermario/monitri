package accounts

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
	"github.com/gomodule/redigo/redis"
	"github.com/jokermario/monitri/internal/email"
	"github.com/jokermario/monitri/internal/entity"
	"github.com/jokermario/monitri/internal/errors"
	"github.com/jokermario/monitri/internal/phone"
	"github.com/jokermario/monitri/pkg/log"
	"golang.org/x/crypto/bcrypt"
	"html/template"
	"io/ioutil"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

type Service interface {
	GetById(ctx context.Context, id string) (Account, error)
	GetAccountByEmail(ctx context.Context, email string) (Account, error)
	GetAccountByPhone(ctx context.Context, phone string) (Account, error)
	Count(ctx context.Context) (int, error)
	UpdateProfile(ctx context.Context, id string, req UpdateAccountRequest) (Account, error)
	DeleteById(ctx context.Context, id string) error
	GetAccounts(ctx context.Context, offset, limit int) ([]Account, error)
	Login(ctx context.Context, req LoginRequest) (*TokenDetails, error)
	CreateAccount(ctx context.Context, req CreateAccountsRequest) error
	ChangePassword (ctx context.Context, id, email string, req ChangePasswordRequest) (error, bool)
	storeAuthKeys(conn redis.Conn, email string, td *TokenDetails) error
	checkAuthKeyIfExist(conn redis.Conn, key string) (string, error)
	logOut(ctx context.Context, conn redis.Conn, keys ...string) error
	generateTokens(identity Identity) (*TokenDetails, error)
	getAccountIdEmailPhone(ctx context.Context, id string) Identity
	refreshToken(identity Identity, redisConn redis.Conn, key string, tokenDetails *TokenDetails) (*TokenDetails, error)
	generateAndSendEmailVerificationToken(ctx context.Context, receiverEmail string) error
	verifyEmailVerificationToken(ctx context.Context, id, token string) (error, bool)
	verifyPhoneVerificationToken(ctx context.Context, id, token string) (error, bool)
	sendLoginNotifEmail(ctx context.Context, email, time, ipaddress, device string)
	generateAndSendPhoneVerificationToken(ctx context.Context, receiverPhone string) error
}

// Identity represents an authenticated accounts identity.
type Identity interface {
	GetAccessID() string
	GetRefreshID() string
	GetID() string
	GetEmail() string
	GetPhone() string
}

type service struct {
	repo                   Repository
	logger                 log.Logger
	emailService           email.Service
	phoneVeriService       phone.Service
	AccessTokenSigningKey  string
	RefreshTokenSigningKey string
	AccessTokenExpiration  int
	RefreshTokenExpiration int
}

type Account struct {
	entity.Accounts
}

type TokenDetails struct {
	AccessToken  string
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

type ChangePasswordRequest struct {
	Password string `json:"new_password"`
}

type UpdateAccountRequest struct {
	Firstname          string `json:"firstname"`
	Middlename         string `json:"middlename"`
	Lastname           string `json:"lastname"`
	Dob                string `json:"dob"`
	Password           string `json:"password"`
	Address            string `json:"address"`
	Bankname           string `json:"bankname"`
	BankAccountNo      string `json:"bank_account_no"`
	ConfirmedEmail     int    `json:"confirmed_email"`
	ConfirmEmailToken  *big.Int
	ConfirmEmailExpiry int64
	ConfirmedPhone     int    `json:"confirmed_phone"`
	Managed            int    `json:"managed"`
	AccountManagerId   string `json:"account_manager_id"`
}

func NewService(repo Repository, logger log.Logger, email email.Service, phoneVeriService phone.Service, AccessTokenSigningKey,
	RefreshTokenSigningKey string, AccessTokenExpiration, RefreshTokenExpiration int) Service {
	return service{repo, logger, email, phoneVeriService, AccessTokenSigningKey,
		RefreshTokenSigningKey, AccessTokenExpiration,
		RefreshTokenExpiration}
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

func (uar UpdateAccountRequest) validate() error {
	return validation.ValidateStruct(&uar,
		validation.Field(&uar.Firstname, validation.Match(regexp.MustCompile("^[a-zA-Z]+$"))),
		validation.Field(&uar.Middlename, validation.Match(regexp.MustCompile("^[a-zA-Z]+$"))),
		validation.Field(&uar.Lastname, validation.Match(regexp.MustCompile("^[a-zA-Z]+$"))),
		validation.Field(&uar.Dob, validation.Required,
			validation.Match(regexp.MustCompile("^\\d{4}\\-(0[1-9]|1[012])\\-(0[1-9]|[12][0-9]|3[01])$"))),
		validation.Field(&uar.Password, validation.Length(8, 0)),
		validation.Field(&uar.Address, is.Alphanumeric),
		validation.Field(&uar.Bankname, validation.Match(regexp.MustCompile("^[a-zA-Z]+$"))),
		validation.Field(&uar.BankAccountNo, validation.Match(regexp.MustCompile("^[0-9]+$"))),
		validation.Field(&uar.ConfirmedEmail, validation.Length(1, 1), is.Int),
		validation.Field(&uar.ConfirmedPhone, validation.Length(1, 1), is.Int),
		validation.Field(&uar.Managed, validation.Length(1, 1), is.Int),
		validation.Field(&uar.AccountManagerId, validation.Length(36, 0)))
}

func (cpr ChangePasswordRequest) validate() error {
	return validation.ValidateStruct(&cpr,
		validation.Field(&cpr.Password, validation.Required, validation.Length(8, 0)))
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

func (s service) GetAccountByPhone(ctx context.Context, phone string) (Account, error) {
	account, err := s.repo.GetAccountByPhone(ctx, phone)
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
		logger.Errorf("an error occurred while trying to get the account with the email: %s\n "+
			"The error is: %s", email, err)
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

func (s service) sendLoginNotifEmail(ctx context.Context, email, time, ipaddress, device string) {
	logger := s.logger.With(ctx, "accounts", email)
	t, _ := template.ParseFiles("internal/email/loginNotificationEmailTemplate.gohtml")
	var body bytes.Buffer
	_ = t.Execute(&body, struct {
		Email     string
		Time      string
		IpAddress string
		Device    string
	}{
		Email:     email,
		Time:      time,
		IpAddress: ipaddress,
		Device:    device,
	})
	contentToString := string(body.Bytes())
	err := s.emailService.SendEmail(email, "Sign-in Notification", contentToString)
	if err != nil {
		logger.Errorf("an error occurred while trying to send login notif email. The error %s", err)
	}
}

func (s service) getAccountIdEmailPhone(ctx context.Context, id string) Identity {
	accountInfo, err := s.repo.GetIdEmailPhone(ctx, id)
	if err != nil {
		return nil
	}
	return entity.Accounts{Id: accountInfo.Id, Email: accountInfo.Email, Phone: accountInfo.Phone}
}

func (s service) CreateAccount(ctx context.Context, req CreateAccountsRequest) error {
	logger := s.logger.With(ctx, "account", req.Email)
	if err := req.validate(); err != nil {
		return err
	}
	id := entity.GenerateID()
	hashedPass, _ := bcrypt.GenerateFromPassword([]byte(req.Password), 12)

	// FIXME I knowingly didn't check for already existing email coz i'm relying on sql uniqueness in DB
	err := s.repo.Create(ctx, entity.Accounts{
		Id:       strings.TrimSpace(id),
		Email:    strings.TrimSpace(req.Email),
		Phone:    strings.TrimSpace(req.Phone),
		Password: string(hashedPass),
	})
	if err != nil {
		return err
	}
	content, _ := ioutil.ReadFile("internal/email/accountCreationEmailTemplate.gohtml")
	contentToString := string(content)
	emailErr := s.emailService.SendEmail(req.Email, "Welcome to Monitri", contentToString)
	if emailErr != nil {
		s.logger.Errorf("an error occurred while trying to send acc creation email.\nThe error: %s", err)
		return emailErr
	}

	logger.Infof("account created successfully")
	return nil
}

func (s service) verifyPassword(password string) error {
	var uppercasePresent bool
	var lowercasePresent bool
	var numberPresent bool
	var specialCharPresent bool
	const minPassLength = 8
	const maxPassLength = 64
	var passLen int
	var errorString string

	for _, ch := range password {
		switch {
		case unicode.IsNumber(ch):
			numberPresent = true
			passLen++
		case unicode.IsUpper(ch):
			uppercasePresent = true
			passLen++
		case unicode.IsLower(ch):
			lowercasePresent = true
			passLen++
		case unicode.IsPunct(ch) || unicode.IsSymbol(ch):
			specialCharPresent = true
			passLen++
		case ch == ' ':
			passLen++
		}
	}
	appendError := func(err string) {
		if len(strings.TrimSpace(errorString)) != 0 {
			errorString += ", " + err
		} else {
			errorString = err
		}
	}
	if !lowercasePresent {
		appendError("lowercase letter missing")
	}
	if !uppercasePresent {
		appendError("uppercase letter missing")
	}
	if !numberPresent {
		appendError("atleast one numeric character required")
	}
	if !specialCharPresent {
		appendError("special character missing")
	}
	if !(minPassLength <= passLen && passLen <= maxPassLength) {
		appendError(fmt.Sprintf("password length must be between %d to %d characters long",
			minPassLength, maxPassLength))
	}

	if len(errorString) != 0 {
		s.logger.Errorf("an error occurred while verifying the password. The Error: %s", errorString)
		return fmt.Errorf(errorString)
	}
	return nil
}

func (s service) ChangePassword (ctx context.Context, id, email string, req ChangePasswordRequest) (error, bool) {
	logger := s.logger.With(ctx, "account", id)
	if strErr := req.validate(); strErr != nil {
		logger.Errorf("validation failed.\n" +
			"The error: %s", strErr)
		return strErr, false
	}
	if err := s.verifyPassword(req.Password); err != nil {
		logger.Errorf("validation failed.\n" +
			"The error: %s", err)
		return err, false
	}
	acc, err := s.GetById(ctx, id)
	if err != nil {
		logger.Errorf("an error occurred while trying to fetch the account.\n" +
			"The error: %s", err)
		return  err, false
	}
	hashedPass, _ := bcrypt.GenerateFromPassword([]byte(req.Password), 12)
	acc.Password = string(hashedPass)
	updateErr := s.repo.Update(ctx, acc.Accounts)
	if updateErr != nil {
		logger.Errorf("an error occurred while trying to update the password to the account row.\n" +
			"The error: %s", updateErr)
		return updateErr, false
	}
	content, _ := ioutil.ReadFile("internal/email/passwordChangedNotificationTemplate.gohtml")
	contentToString := string(content)
	emailErr := s.emailService.SendEmail(email, "Password Change Notification", contentToString)
	if emailErr != nil {
		s.logger.Errorf("an error occurred while trying to send pass change notif email.\nThe error: %s", err)
		return emailErr, false
	}
	return nil, true
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
	return td, nil
}

func (s service) refreshToken(identity Identity, redisConn redis.Conn,
	key string, tokenDetails *TokenDetails) (*TokenDetails, error) {
	td := &TokenDetails{}
	var accerr error
	var referr error
	td.AtExpires = time.Now().Add(time.Duration(s.AccessTokenExpiration) * time.Hour).Unix()
	td.RtExpires = time.Now().Add(time.Duration(s.RefreshTokenExpiration) * time.Hour).Unix()
	td.AccessUuid = tokenDetails.AccessUuid
	td.RefreshUuid = tokenDetails.RefreshUuid

	td.AccessToken, accerr = s.generateAccessToken(identity, td.AccessUuid, td.AtExpires)
	if accerr != nil {
		return nil, accerr
	}
	td.RefreshToken, referr = s.generateRefreshToken(identity, td.RefreshUuid, td.RtExpires)
	if referr != nil {
		return nil, referr
	}

	redisErr := s.storeAuthKeys(redisConn, key, tokenDetails)
	if redisErr != nil {
		return nil, redisErr
	}
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
		"exp":         expiryTime,
	}).SignedString([]byte(s.RefreshTokenSigningKey))
}

func (s service) generateAndSendEmailVerificationToken(ctx context.Context, receiverEmail string) error {
	logger := s.logger.With(ctx, "account", receiverEmail)
	RandomCrypto, _ := rand.Prime(rand.Reader, 20)
	t, _ := template.ParseFiles("internal/email/emailVerificationTokenTemplate.gohtml")
	var body bytes.Buffer
	_ = t.Execute(&body, struct {
		Token *big.Int
	}{
		Token: RandomCrypto,
	})
	account, err := s.GetAccountByEmail(ctx, receiverEmail)
	if err != nil {
		logger.Errorf("an error occurred while trying to get account by email.\nThe error: %s, err")
		return err
	}
	account.ConfirmEmailToken = int(RandomCrypto.Int64())
	account.ConfirmEmailExpiry = time.Now().Add(time.Duration(30) * time.Minute).Unix()

	updateErr := s.repo.Update(ctx, account.Accounts)
	if updateErr != nil {
		logger.Errorf("an error occurred while trying to update the token to the account row.\n" +
			"The error: %s, updateErr")
		return updateErr
	}
	contentToString := string(body.Bytes())
	sendmailErr := s.emailService.SendEmail(receiverEmail, "Email verification", contentToString)
	if sendmailErr != nil {
		logger.Errorf("an error occurred while trying to send email.\nThe error: %s", sendmailErr)
		return sendmailErr
	}
	return nil
}

func (s service) verifyEmailVerificationToken(ctx context.Context, id, token string) (error, bool) {
	logger := s.logger.With(ctx, "account", id)
	acc, err := s.GetById(ctx, id)
	if err != nil {
		logger.Errorf("an error occurred while trying to verify email token.\nThe error: %s, err")
		return err, false
	}
	tokenExpiry := time.Unix(acc.ConfirmEmailExpiry, 0)
	now := time.Now()

	if int64(tokenExpiry.Sub(now).Seconds()) < 0 {
		logger.Errorf("email token expired")
		return nil, false
	}

	i, _ := strconv.Atoi(token)

	if i != acc.ConfirmEmailToken {
		return nil, false
	}

	acc.ConfirmedEmail = 1
	updateErr := s.repo.Update(ctx, acc.Accounts)
	if updateErr != nil {
		logger.Errorf("an error occurred while trying to update confirmed email status after veri.\n" +
			"The error: %s, err")
	}

	return nil, true
}

func (s service) generateAndSendPhoneVerificationToken(ctx context.Context, receiverPhone string) error {
	logger := s.logger.With(ctx, "account", receiverPhone)
	RandomCrypto, _ := rand.Prime(rand.Reader, 20)
	account, err := s.GetAccountByPhone(ctx, receiverPhone)
	if err != nil {
		logger.Errorf("an error occurred while trying to get account by phone.\nThe error: %s", err)
		return err
	}
	account.ConfirmPhoneToken = int(RandomCrypto.Int64())
	account.ConfirmPhoneExpiry = time.Now().Add(time.Duration(10) * time.Minute).Unix()
	updateErr := s.repo.Update(ctx, account.Accounts)
	if updateErr != nil {
		logger.Errorf("an error occurred while trying to update the token to the account row.\n"+
			"The error: %s", updateErr)
		return updateErr
	}
	tokenToString := strconv.Itoa(int(RandomCrypto.Int64()))
	_, ok := s.phoneVeriService.SendSMSToMobile(receiverPhone, "Your verification token is "+tokenToString+
		". it expires in 10 minutes")
	if !ok {
		logger.Errorf("an error occurred while trying to send token to mobile")
		return nil
	}
	return nil
}

func (s service) verifyPhoneVerificationToken(ctx context.Context, id, token string) (error, bool) {
	logger := s.logger.With(ctx, "account", id)
	acc, err := s.GetById(ctx, id)
	if err != nil {
		logger.Errorf("an error occurred while trying to verify phone token.\nThe error: %s, err")
		return err, false
	}
	tokenExpiry := time.Unix(acc.ConfirmPhoneExpiry, 0)
	now := time.Now()

	if int64(tokenExpiry.Sub(now).Seconds()) < 0 {
		logger.Errorf("phone token expired")
		return nil, false
	}

	i, _ := strconv.Atoi(token)

	if i != acc.ConfirmPhoneToken {
		return nil, false
	}

	acc.ConfirmedPhone = 1
	updateErr := s.repo.Update(ctx, acc.Accounts)
	if updateErr != nil {
		logger.Errorf("an error occurred while trying to update confirmed phone status after veri.\n" +
			"The error: %s, err")
	}

	return nil, true
}

//redis
func (s service) storeAuthKeys(conn redis.Conn, email string, td *TokenDetails) error {
	at := time.Unix(td.AtExpires, 0) //converting unix to UTC(to time object)
	rt := time.Unix(td.RtExpires, 0)
	now := time.Now()

	errAccess := s.repo.SetRedisKey(conn, int64(at.Sub(now).Seconds()), td.AccessUuid, email)
	if errAccess != nil {
		return errAccess
	}
	errRefresh := s.repo.SetRedisKey(conn, int64(rt.Sub(now).Seconds()), td.RefreshUuid, email)
	if errRefresh != nil {
		return errRefresh
	}
	return nil
}

func (s service) checkAuthKeyIfExist(conn redis.Conn, key string) (string, error) {
	val, err := s.repo.GetRedisKey(conn, key)
	return val, err
}

func (s service) logOut(ctx context.Context, conn redis.Conn, keys ...string) error {
	logger := s.logger.With(ctx, "accessUUID", keys)
	_ = s.repo.DeleteRedisKeys(conn, keys...)
	logger.Infof("deleted redis key %s", keys)

	return nil
}
