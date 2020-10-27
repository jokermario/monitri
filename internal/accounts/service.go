package accounts

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"database/sql"
	"encoding/hex"
	"encoding/json"
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
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
	"html/template"
	"image/png"
	"io"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

type Service interface {
	getAccountById(ctx context.Context, id string) (Account, error)
	getAccountByEmail(ctx context.Context, email string) (Account, error)
	getAccountByPhone(ctx context.Context, phone string) (Account, error)
	count(ctx context.Context) (int, error)
	updateProfile(ctx context.Context, id string, req UpdateAccountRequest) (Account, error)
	deleteById(ctx context.Context, id string) error
	getAccounts(ctx context.Context, offset, limit int) ([]Account, error)
	login(ctx context.Context, req LoginRequest) (*TokenDetails, error, string)
	createAccount(ctx context.Context, req CreateAccountsRequest) error
	changePassword(ctx context.Context, id, email string, req ChangePasswordRequest) (error, bool)
	storeAuthKeys(conn redis.Conn, email string, td *TokenDetails) error
	checkIfKeyExist(conn redis.Conn, key string) (string, error)
	logOut(ctx context.Context, conn redis.Conn, keys ...string) error
	generateTokens(identity Identity) (*TokenDetails, error)
	getAccountIdEmailPhone(ctx context.Context, id string) Identity
	refreshToken(identity Identity, redisConn redis.Conn, key string, tokenDetails *TokenDetails) (*TokenDetails, error)
	generateAndSendEmailToken(ctx context.Context, receiverEmail, purpose string) error
	verifyEmailToken(ctx context.Context, id, token, purpose string) (error, bool)
	verifyPhoneToken(ctx context.Context, id, token, purpose string) (error, bool)
	sendLoginNotifEmail(ctx context.Context, email, time, ipaddress, device string)
	generateAndSendPhoneToken(ctx context.Context, receiverPhone, purpose string) error
	setupTOTP(ctx context.Context, email string) (string, []byte, error)
	validateTOTPFirstTime(ctx context.Context, id, email, passcode, secret string) bool
	validateTOTP(ctx context.Context, passcode, secret string) bool
	LoginWithMobile2FA(ctx context.Context, req AdditionalSecLoginRequest) (*TokenDetails, error)
	loginWithEmail2FA(ctx context.Context, req AdditionalSecLoginRequest) (*TokenDetails, error)
	loginWithPhone2FA(ctx context.Context, req AdditionalSecLoginRequest) (*TokenDetails, error)
	set2FA(ctx context.Context, id, email, phone, Type string) error
	aesEncrypt(data string) ([]byte, error)
	aesDecrypt(encryptedText string) ([]byte, error)
	completedVerification(ctx context.Context, email string) (error, interface{}, bool)
	getTransactionByTransRef(ctx context.Context, transRef string) (Transaction, error)
	//getLatestTransactionInfo(ctx context.Context, accountId string) (Transaction, error)
	createTrans(ctx context.Context, id, transRef string) error
	updateTrans(ctx context.Context, id, transRef, status, transType, currency, requestPayload string, amount, currentBalance int) error
	webHookValid(payload, payStackSig string) bool
	verifyOnPaystack(transRef string) bool
	initiateTransaction(ctx context.Context, id string, req InitiateTransactionRequest) ([]byte, error)
	getBanks(ctx context.Context) ([]byte, error)
	//flagIP(conn redis.Conn, ip string) error
}

// Identity represents an authenticated accounts identity.
type Identity interface {
	GetAccessID() string
	GetRefreshID() string
	GetID() string
	GetEmail() string
	GetPhone() string
	GetTOTPSecret() string
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
	EncKey                 string
	PSec                   string
	PaystackUrl            string
}

type Account struct {
	entity.Accounts
}

type Setting struct {
	entity.Settings
}

type Transaction struct {
	entity.Transactions
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

type AdditionalSecLoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Token    string `json:"token"`
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
	Firstname  string `json:"firstname,omitempty"`
	Middlename string `json:"middlename,omitempty"`
	Lastname   string `json:"lastname,omitempty"`
	Dob        string `json:"dob,omitempty"`
	Password   string `json:"password,omitempty"`
	Address    string `json:"address,omitempty"`
}

type Authorization struct {
	AuthorizationCode string `json:"authorization_code,omitempty"`
	Bin               string `json:"bin,omitempty"`
	Last4             string `json:"last4,omitempty"`
	ExpMonth          string `json:"exp_month,omitempty"`
	ExpYear           string `json:"exp_year,omitempty"`
	Channel           string `json:"channel,omitempty"`
	CardType          string `json:"card_type,omitempty"`
	Bank              string `json:"bank,omitempty"`
	CountryCode       string `json:"country_code,omitempty"`
	Brand             string `json:"brand,omitempty"`
	Signature         string `json:"signature,omitempty"`
	Reusable          bool   `json:"reusable,omitempty"`
}

type TransactionTimeline struct {
	TimeSpent      int                      `json:"time_spent,omitempty"`
	Attempts       int                      `json:"attempts,omitempty"`
	Authentication string                   `json:"authentication,omitempty"` // TODO: confirm type
	Errors         int                      `json:"errors,omitempty"`
	Success        bool                     `json:"success,omitempty"`
	Mobile         bool                     `json:"mobile,omitempty"`
	Input          []string                 `json:"input,omitempty"` // TODO: confirm type
	Channel        string                   `json:"channel,omitempty"`
	History        []map[string]interface{} `json:"history,omitempty"`
}

type Customer struct {
	ID           int                      `json:"id,omitempty"`
	FirstName    string                   `json:"first_name,omitempty"`
	LastName     string                   `json:"last_name,omitempty"`
	Email        string                   `json:"email,omitempty"`
	CustomerCode string                   `json:"customer_code,omitempty"`
	Phone        string                   `json:"phone,omitempty"`
	Metadata     []map[string]interface{} `json:"metadata,omitempty"`
	RiskAction   string                   `json:"risk_action"`
}

type Plan struct {
	ID                int     `json:"id,omitempty"`
	CreatedAt         string  `json:"created_at,omitempty"`
	UpdatedAt         string  `json:"updated_at,omitempty"`
	Domain            string  `json:"domain,omitempty"`
	Integration       int     `json:"integration,omitempty"`
	Name              string  `json:"name,omitempty"`
	Description       string  `json:"description,omitempty"`
	PlanCode          string  `json:"plan_code,omitempty"`
	Amount            float32 `json:"amount,omitempty"`
	Interval          string  `json:"interval,omitempty"`
	SendInvoices      bool    `json:"send_invoices,omitempty"`
	SendSMS           bool    `json:"send_sms,omitempty"`
	Currency          string  `json:"currency,omitempty"`
	InvoiceLimit      float32 `json:"invoice_limit,omitempty"`
	HostedPage        string  `json:"hosted_page,omitempty"`
	HostedPageURL     string  `json:"hosted_page_url,omitempty"`
	HostedPageSummary string  `json:"hosted_page_summary,omitempty"`
}

type DataInChargeSuccessPayload struct {
	Id              int                    `json:"id,omitempty"`
	Domain          string                 `json:"domain,omitempty"`
	Status          string                 `json:"status,omitempty"`
	Reference       string                 `json:"reference,omitempty"`
	Amount          int                    `json:"amount,omitempty"`
	Message         string                 `json:"message,omitempty"`
	GatewayResponse string                 `json:"gateway_response,omitempty"`
	PaidAt          string                 `json:"paid_at,omitempty"`
	CreatedAt       string                 `json:"created_at,omitempty"`
	Channel         string                 `json:"channel,omitempty"`
	Currency        string                 `json:"currency,omitempty"`
	IpAddress       string                 `json:"ip_address,omitempty"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
	Log             TransactionTimeline    `json:"log,omitempty"`
	Fees            string                 `json:"fees,omitempty"`
	Customer        Customer               `json:"customer,omitempty"`
	Authorization   Authorization          `json:"authorization,omitempty"`
	Plan            Plan                   `json:"plan,omitempty"`
}

type DataInVerifyPaymentResponsePayload struct {
	Amount          int                    `json:"amount,omitempty"`
	Currency        string                 `json:"currency,omitempty"`
	TransactionDate string                 `json:"transaction_date,omitempty"`
	Status          string                 `json:"status,omitempty"`
	Reference       string                 `json:"reference,omitempty"`
	Domain          string                 `json:"domain,omitempty"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
	GatewayResponse string                 `json:"gateway_response,omitempty"`
	Message         interface{}            `json:"message,omitempty"`
	Channel         string                 `json:"channel,omitempty"`
	IpAddress       string                 `json:"ip_address,omitempty"`
	Log             TransactionTimeline    `json:"log,omitempty"`
	Fees            string                 `json:"fees,omitempty"`
	Authorization   Authorization          `json:"authorization,omitempty"`
	Customer        Customer               `json:"customer,omitempty"`
	Plan            string                 `json:"plan,omitempty"`
	RequestedAmount int                    `json:"requested_amount,omitempty"`
}

type ChargeSuccessPayload struct {
	Event string                     `json:"event"`
	Data  DataInChargeSuccessPayload `json:"data"`
}

type VerifyPaymentResponsePayload struct {
	Status  bool                               `json:"status,omitempty"`
	Message string                             `json:"message,omitempty"`
	Data    DataInVerifyPaymentResponsePayload `json:"data,omitempty"`
}

type InitiateTransactionRequest struct {
	Amount    string `json:"amount"`
	Email     string `json:"email"`
	Reference string `json:"reference,omitempty"`
	//Channels []string `json:"channels,omitempty"`
}

type DataInPaystackGeneralResponse struct {
	AuthorizationUrl string                 `json:"authorization_url,omitempty"`
	AccessCode       string                 `json:"access_code,omitempty"`
	Reference        string                 `json:"reference,omitempty"`
	Type             string                 `json:"type,omitempty"`
	Name             string                 `json:"name,omitempty"`
	Description      string                 `json:"description,omitempty"`
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
	Domain           string                 `json:"domain,omitempty"`
	Details          map[string]interface{} `json:"details,omitempty"`
	Currency         string                 `json:"currency,omitempty"`
	RecipientCode    string                 `json:"recipient_code,omitempty"`
	Active           bool                   `json:"active,omitempty"`
	Id               int                    `json:"id,omitempty"`
	CreatedAt        string                 `json:"createdAt,omitempty"`
	UpdatedAt        string                 `json:"updatedAt,omitempty"`
}

type PaystackGeneralResponse struct {
	Status  bool                          `json:"status,omitempty"`
	Message string                        `json:"message,omitempty"`
	Data    DataInPaystackGeneralResponse `json:"data,omitempty"`
}

type SetBankDetailsRequest struct {
	Type          string `json:"type,omitempty"`
	Name          string `json:"name,omitempty"`
	AccountNumber string `json:"account_number"`
	BankCode      string `json:"bank_code"`
}

func NewService(repo Repository, logger log.Logger, email email.Service, phoneVeriService phone.Service, AccessTokenSigningKey,
	RefreshTokenSigningKey string, AccessTokenExpiration, RefreshTokenExpiration int, EncKey, PSec, PaystackUrl string) Service {
	return service{repo, logger, email, phoneVeriService, AccessTokenSigningKey,
		RefreshTokenSigningKey, AccessTokenExpiration,
		RefreshTokenExpiration, EncKey, PSec, PaystackUrl}
}

func (lr LoginRequest) validate() error {
	return validation.ValidateStruct(&lr,
		validation.Field(&lr.Email, validation.Required, is.Email),
		validation.Field(&lr.Password, validation.Required))
}

func (aslr AdditionalSecLoginRequest) validate() error {
	return validation.ValidateStruct(&aslr,
		validation.Field(&aslr.Email, validation.Required, is.Email),
		validation.Field(&aslr.Password, validation.Required),
		validation.Field(&aslr.Token, validation.Required))
}

func (car CreateAccountsRequest) validate() error {
	return validation.ValidateStruct(&car,
		validation.Field(&car.Email, validation.Required, is.Email),
		validation.Field(&car.Phone, validation.Required),
		validation.Field(&car.Password, validation.Required, validation.Length(8, 0)))
}

func (uar UpdateAccountRequest) validate() error {
	return validation.ValidateStruct(&uar,
		validation.Field(&uar.Firstname, validation.Required, validation.Match(regexp.MustCompile("^[a-zA-Z]+$"))),
		validation.Field(&uar.Middlename, validation.Match(regexp.MustCompile("^[a-zA-Z]+$"))),
		validation.Field(&uar.Lastname, validation.Required, validation.Match(regexp.MustCompile("^[a-zA-Z]+$"))),
		validation.Field(&uar.Dob, validation.Required,
			validation.Match(regexp.MustCompile("^\\d{4}-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01])+$"))),
		validation.Field(&uar.Address, validation.Required, validation.Match(regexp.MustCompile("^[a-z A-Z0-9,.]+$"))))
	//validation.Field(&uar.Bankname, validation.Match(regexp.MustCompile("^[a-zA-Z]+$"))),
	//validation.Field(&uar.BankAccountNo, validation.Match(regexp.MustCompile("^[0-9]+$"))),
	//validation.Field(&uar.ConfirmedEmail, validation.Length(1, 1), is.Int),
	//validation.Field(&uar.ConfirmedPhone, validation.Length(1, 1), is.Int),
	//validation.Field(&uar.Managed, validation.Length(1, 1), is.Int),
	//validation.Field(&uar.AccountManagerId, validation.Length(36, 0)))
}

func (cpr ChangePasswordRequest) validate() error {
	return validation.ValidateStruct(&cpr,
		validation.Field(&cpr.Password, validation.Required, validation.Length(8, 0)))
}

func (itr InitiateTransactionRequest) validate() error {
	return validation.ValidateStruct(&itr,
		validation.Field(&itr.Amount, validation.Required, validation.Match(regexp.MustCompile("^[0-9]+$"))),
		validation.Field(&itr.Email, validation.Required, is.Email))
}

func (sbdr SetBankDetailsRequest) validate() error {
	return validation.ValidateStruct(&sbdr,
		validation.Field(&sbdr.AccountNumber, validation.Required, validation.Match(regexp.MustCompile("^[0-9]+$"))),
		validation.Field(&sbdr.BankCode, validation.Required, validation.Match(regexp.MustCompile("^[0-9]+$"))))
}

//-------------------------------------------------NON-SPECIFIC FUNCTIONS-----------------------------------------------

// Login authenticates a accounts and generates a JWT token if authentication succeeds.
// Otherwise, an error is returned.
func (s service) login(ctx context.Context, req LoginRequest) (*TokenDetails, error, string) {
	if err := req.validate(); err != nil {
		return nil, err, ""
	}
	if identity := s.authenticate(ctx, req.Email, req.Password); identity != nil {

		settingsInfo, _ := s.repo.GetSettingsById(ctx, identity.GetID())

		if settingsInfo.TwofaGoogleAuth == 1 {
			TokenDetails, err := s.generateTokens(identity)
			return TokenDetails, err, "mobile2FA"
		} else if settingsInfo.TwofaEmail == 1 {
			_ = s.generateAndSendEmailToken(ctx, req.Email, "login2fa")
			TokenDetails, err := s.generateTokens(identity)
			return TokenDetails, err, "email2FA"
		} else if settingsInfo.TwofaPhone == 1 {
			_ = s.generateAndSendPhoneToken(ctx, identity.GetPhone(), "login2fa")
			TokenDetails, err := s.generateTokens(identity)
			return TokenDetails, err, "phone2FA"
		} else {
			TokenDetails, err := s.generateTokens(identity)
			return TokenDetails, err, ""
		}
	}
	return nil, errors.Unauthorized(""), ""
}

func (s service) LoginWithMobile2FA(ctx context.Context, req AdditionalSecLoginRequest) (*TokenDetails, error) {
	if err := req.validate(); err != nil {
		return nil, err
	}
	if identity := s.authenticate(ctx, req.Email, req.Password); identity != nil {
		if ok := totp.Validate(req.Token, identity.GetTOTPSecret()); !ok {
			return nil, errors.Unauthorized("")
		}
		return s.generateTokens(identity)
	}
	return nil, errors.Unauthorized("")
}

func (s service) loginWithEmail2FA(ctx context.Context, req AdditionalSecLoginRequest) (*TokenDetails, error) {
	if err := req.validate(); err != nil {
		return nil, err
	}
	if identity := s.authenticate(ctx, req.Email, req.Password); identity != nil {
		_, ok := s.verifyEmailToken(ctx, identity.GetID(), req.Token, "login2fa")
		if !ok {
			return nil, errors.Unauthorized("")
		}
		return s.generateTokens(identity)
	}
	return nil, errors.Unauthorized("")
}

func (s service) loginWithPhone2FA(ctx context.Context, req AdditionalSecLoginRequest) (*TokenDetails, error) {
	if err := req.validate(); err != nil {
		return nil, err
	}
	if identity := s.authenticate(ctx, req.Email, req.Password); identity != nil {
		_, ok := s.verifyPhoneToken(ctx, identity.GetID(), req.Token, "login2fa")
		if !ok {
			return nil, errors.Unauthorized("")
		}
		return s.generateTokens(identity)
	}
	return nil, errors.Unauthorized("")
}

func (s service) completedVerification(ctx context.Context, email string) (error, interface{}, bool) {
	logger := s.logger.With(ctx, "account", email)
	acc, err := s.getAccountByEmail(ctx, email)
	errstrings := make(map[string]interface{})
	if err != nil {
		logger.Errorf("an error occurred while trying to get user account information.\nThe error: %s", err)
		errstrings["error"] = "Must verify email, phone and update profile before you continue"
		return err, errstrings["error"], false
	}
	if acc.ConfirmedEmail != 1 {
		errstrings["email"] = "email not verified"
	}
	if acc.ConfirmedPhone != 1 {
		errstrings["phone"] = "phone not verified"
	}
	if acc.Dob == "" {
		errstrings["profile"] = "profile not updated"
	}

	fmt.Println(len(errstrings))
	fmt.Println(errstrings)

	if errstrings["email"] != nil || errstrings["phone"] != nil || errstrings["profile"] != nil {
		return errors.InternalServerError("Must verify email, phone and update profile before you continue"), errstrings, false
	} else {
		return nil, nil, true
	}
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

func (s service) aesEncrypt(data string) ([]byte, error) {
	convertDataToByte := []byte(data)
	keyToByte := []byte(s.EncKey)

	//generate a new aes cipher using the key
	c, err := aes.NewCipher(keyToByte)
	if err != nil {
		s.logger.Errorf("an error occurred while trying to generate a cipher")
		return nil, err
	}

	//using the galois counter mode (GCM) mode of operation its better than the CBC mode.
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		s.logger.Errorf("an error occurred while trying to generate a new GCM")
		return nil, err
	}

	//create a new byte array the size of the GCM Nonce.
	nonce := make([]byte, gcm.NonceSize())

	//populate the nonce with cryptographically secure random sequence
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		s.logger.Errorf("an error occurred while trying to generate a new GCM")
		return nil, err
	}

	return gcm.Seal(nonce, nonce, convertDataToByte, nil), nil
}

func (s service) aesDecrypt(encryptedText string) ([]byte, error) {

	encryptedTextToByte := []byte(encryptedText)

	keyToByte := []byte(s.EncKey)

	c, err := aes.NewCipher(keyToByte)
	if err != nil {
		s.logger.Errorf("in decrypt: an error occurred while trying to generate a cipher")
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		s.logger.Errorf("in decrypt: an error occurred while trying to generate a new GCM")
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(encryptedText) < nonceSize {
		s.logger.Errorf("in decrypt: an error occurred while checking if encrypted data matched the nonce size")
		return nil, err
	}

	nonce, ciphertext := encryptedTextToByte[:nonceSize], encryptedTextToByte[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		s.logger.Errorf("in decrypt: an error occurred while trying to decrypt the encrypted text")
		return nil, err
	}

	return plaintext, nil
}

func (s service) webHookValid(payload, payStackSig string) bool {
	hmac512 := hmac.New(sha512.New, []byte(s.PSec))
	hmac512.Write([]byte(payload))
	payloadSig := hex.EncodeToString(hmac512.Sum(nil))
	if !hmac.Equal([]byte(payloadSig), []byte(payStackSig)) {
		return false
	}
	return true
}

//---------------------------------------------------ACCOUNT FUNCTIONS--------------------------------------------------

func (s service) getAccountById(ctx context.Context, id string) (Account, error) {
	account, err := s.repo.GetAccountById(ctx, id)
	if err != nil {
		return Account{}, err
	}
	return Account{account}, err
}

func (s service) getSettingsById(ctx context.Context, id string) (Setting, error) {
	settingsAccount, err := s.repo.GetSettingsById(ctx, id)
	if err != nil {
		return Setting{}, err
	}
	return Setting{settingsAccount}, err
}

func (s service) getAccountByEmail(ctx context.Context, email string) (Account, error) {
	account, err := s.repo.GetAccountByEmail(ctx, email)
	if err != nil {
		return Account{}, err
	}
	return Account{account}, err
}

func (s service) getAccountByPhone(ctx context.Context, phone string) (Account, error) {
	account, err := s.repo.GetAccountByPhone(ctx, phone)
	if err != nil {
		return Account{}, err
	}
	return Account{account}, err
}

func (s service) count(ctx context.Context) (int, error) {
	return s.repo.AccountCount(ctx)
}

func (s service) updateProfile(ctx context.Context, id string, req UpdateAccountRequest) (Account, error) {
	if err := req.validate(); err != nil {
		return Account{}, err
	}
	account, err := s.getAccountById(ctx, id)
	if err != nil {
		return Account{}, err
	}
	account.Firstname = strings.TrimSpace(req.Firstname)
	account.Middlename = strings.TrimSpace(req.Middlename)
	account.Lastname = strings.TrimSpace(req.Lastname)
	account.Dob = strings.TrimSpace(req.Dob)
	account.Address = strings.TrimSpace(req.Address)
	account.UpdatedAt = time.Now()

	if err := s.repo.AccountUpdate(ctx, account.Accounts); err != nil {
		return Account{}, err
	}
	return account, nil
}

func (s service) deleteById(ctx context.Context, id string) error {
	_, err := s.getAccountById(ctx, id)
	if err != nil {
		return err
	}
	if err := s.repo.AccountDelete(ctx, id); err != nil {
		return err
	}
	return nil
}

//func (s service) GenerateEmailVerificationToken(ctx context.Context, )

func (s service) getAccounts(ctx context.Context, offset, limit int) ([]Account, error) {
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
	accountInfo, err := s.repo.GetAccountIdEmailPhone(ctx, id)
	if err != nil {
		return nil
	}
	return entity.Accounts{Id: accountInfo.Id, Email: accountInfo.Email, Phone: accountInfo.Phone}
}

func (s service) createAccount(ctx context.Context, req CreateAccountsRequest) error {
	logger := s.logger.With(ctx, "account", req.Email)
	if err := req.validate(); err != nil {
		return err
	}
	if err := s.verifyPassword(req.Password); err != nil {
		logger.Errorf("validation failed.\n"+
			"The error: %s", err)
		return err
	}
	id := entity.GenerateID()
	hashedPass, _ := bcrypt.GenerateFromPassword([]byte(req.Password), 12)

	// FIXME I knowingly didn't check for already existing email coz i'm relying on sql uniqueness in DB
	err := s.repo.AccountCreate(ctx, entity.Accounts{
		Id:        strings.TrimSpace(id),
		Email:     strings.TrimSpace(req.Email),
		Phone:     strings.TrimSpace(req.Phone),
		Password:  string(hashedPass),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
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
	//var specialCharPresent bool
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
		//case unicode.IsPunct(ch) || unicode.IsSymbol(ch):
		//	specialCharPresent = true
		//	passLen++
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
	//if !specialCharPresent {
	//	appendError("special character missing")
	//}
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

func (s service) changePassword(ctx context.Context, id, email string, req ChangePasswordRequest) (error, bool) {
	logger := s.logger.With(ctx, "account", id)
	if strErr := req.validate(); strErr != nil {
		logger.Errorf("validation failed.\n"+
			"The error: %s", strErr)
		return strErr, false
	}
	if err := s.verifyPassword(req.Password); err != nil {
		logger.Errorf("validation failed.\n"+
			"The error: %s", err)
		return err, false
	}
	acc, err := s.getAccountById(ctx, id)
	if err != nil {
		logger.Errorf("an error occurred while trying to fetch the account.\n"+
			"The error: %s", err)
		return err, false
	}
	hashedPass, _ := bcrypt.GenerateFromPassword([]byte(req.Password), 12)
	acc.Password = string(hashedPass)
	updateErr := s.repo.AccountUpdate(ctx, acc.Accounts)
	if updateErr != nil {
		logger.Errorf("an error occurred while trying to update the password to the account row.\n"+
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

func (s service) generateAndSendEmailToken(ctx context.Context, receiverEmail, purpose string) error {
	logger := s.logger.With(ctx, "account", receiverEmail)
	RandomCrypto, _ := rand.Prime(rand.Reader, 20)
	if purpose == "login2fa" {
		t, _ := template.ParseFiles("internal/email/email2FANotificationEmailTemplate.gohtml")
		var body bytes.Buffer
		_ = t.Execute(&body, struct {
			Token *big.Int
		}{
			Token: RandomCrypto,
		})
		account, err := s.getAccountByEmail(ctx, receiverEmail)
		if err != nil {
			logger.Errorf("an error occurred while trying to get account by email.\nThe error: %s, err")
			return err
		}
		account.LoginEmailToken = int(RandomCrypto.Int64())
		account.LoginEmailExpiry = time.Now().Add(time.Duration(5) * time.Minute).Unix()

		updateErr := s.repo.AccountUpdate(ctx, account.Accounts)
		if updateErr != nil {
			logger.Errorf("an error occurred while trying to update the token to the account row.\n" +
				"The error: %s, updateErr")
			return updateErr
		}
		contentToString := string(body.Bytes())
		sendmailErr := s.emailService.SendEmail(receiverEmail, "2FA login Token", contentToString)
		if sendmailErr != nil {
			logger.Errorf("an error occurred while trying to send email.\nThe error: %s", sendmailErr)
			return sendmailErr
		}
	}

	if purpose == "verification" {
		t, _ := template.ParseFiles("internal/email/emailVerificationTokenTemplate.gohtml")
		var body bytes.Buffer
		_ = t.Execute(&body, struct {
			Token *big.Int
		}{
			Token: RandomCrypto,
		})
		account, err := s.getAccountByEmail(ctx, receiverEmail)
		if err != nil {
			logger.Errorf("an error occurred while trying to get account by email.\nThe error: %s, err")
			return err
		}
		account.ConfirmEmailToken = int(RandomCrypto.Int64())
		account.ConfirmEmailExpiry = time.Now().Add(time.Duration(30) * time.Minute).Unix()

		updateErr := s.repo.AccountUpdate(ctx, account.Accounts)
		if updateErr != nil {
			logger.Errorf("an error occurred while trying to update the token to the account row.\n" +
				"The error: %s, updateErr")
			return updateErr
		}
		contentToString := string(body.Bytes())
		sendmailErr := s.emailService.SendEmail(receiverEmail, "Confirm email address", contentToString)
		if sendmailErr != nil {
			logger.Errorf("an error occurred while trying to send email.\nThe error: %s", sendmailErr)
			return sendmailErr
		}
	}
	return nil
}

func (s service) verifyEmailToken(ctx context.Context, id, token, purpose string) (error, bool) {
	logger := s.logger.With(ctx, "account", id)
	acc, err := s.getAccountById(ctx, id)
	if err != nil {
		logger.Errorf("an error occurred while trying to verify email token.\nThe error: %s", err)
		return err, false
	}
	if purpose == "login2fa" {
		tokenExpiry := time.Unix(acc.LoginEmailExpiry, 0)
		now := time.Now()

		if int64(tokenExpiry.Sub(now).Seconds()) < 0 {
			logger.Errorf("email token expired")
			return errors.InternalServerError("emailTokenExpired"), false
		}

		i, _ := strconv.Atoi(token)

		if i != acc.LoginEmailToken {
			return nil, false
		}
		//fmt.Println("he")
	}

	if purpose == "verification" {
		tokenExpiry := time.Unix(acc.ConfirmEmailExpiry, 0)
		now := time.Now()

		if int64(tokenExpiry.Sub(now).Seconds()) < 0 {
			logger.Errorf("email token expired")
			return errors.InternalServerError("emailTokenExpired"), false
		}

		i, _ := strconv.Atoi(token)

		if i != acc.ConfirmEmailToken {
			return nil, false
		}

		acc.ConfirmedEmail = 1
		updateErr := s.repo.AccountUpdate(ctx, acc.Accounts)
		if updateErr != nil {
			logger.Errorf("an error occurred while trying to update confirmed email status after veri.\n"+
				"The error: %s", updateErr)
		}
	}

	return nil, true
}

func (s service) generateAndSendPhoneToken(ctx context.Context, receiverPhone, purpose string) error {
	logger := s.logger.With(ctx, "account", receiverPhone)
	RandomCrypto, _ := rand.Prime(rand.Reader, 20)
	account, err := s.getAccountByPhone(ctx, receiverPhone)
	if err != nil {
		logger.Errorf("an error occurred while trying to get account by phone.\nThe error: %s", err)
		return err
	}

	if purpose == "login2fa" {
		account.LoginPhoneToken = int(RandomCrypto.Int64())
		account.LoginPhoneExpiry = time.Now().Add(time.Duration(10) * time.Minute).Unix()
		account.UpdatedAt = time.Now()
		updateErr := s.repo.AccountUpdate(ctx, account.Accounts)
		if updateErr != nil {
			logger.Errorf("an error occurred while trying to update the token to the account row.\n"+
				"The error: %s", updateErr)
			return updateErr
		}

		tokenToString := strconv.Itoa(int(RandomCrypto.Int64()))

		_, ok := s.phoneVeriService.SendSMSToMobile(receiverPhone, "Your login 2FA token is "+tokenToString+
			". it expires in 10 minutes")
		if !ok {
			logger.Errorf("an error occurred while trying to send token to mobile")
			return nil
		}
	}

	if purpose == "verification" {
		account.ConfirmPhoneToken = int(RandomCrypto.Int64())
		account.ConfirmPhoneExpiry = time.Now().Add(time.Duration(10) * time.Minute).Unix()
		account.UpdatedAt = time.Now()
		updateErr := s.repo.AccountUpdate(ctx, account.Accounts)
		if updateErr != nil {
			logger.Errorf("an error occurred while trying to update the token to the account row.\n"+
				"The error: %s", updateErr)
			return updateErr
		}

		tokenToString := strconv.Itoa(int(RandomCrypto.Int64()))

		_, ok := s.phoneVeriService.SendSMSToMobile(receiverPhone, "Your verification token is "+tokenToString+
			". it expires in 10 minutes")
		fmt.Println("here")
		if !ok {
			logger.Errorf("an error occurred while trying to send token to mobile")
			return nil
		}
	}

	return nil
}

func (s service) verifyPhoneToken(ctx context.Context, id, token, purpose string) (error, bool) {
	logger := s.logger.With(ctx, "account", id)
	acc, err := s.getAccountById(ctx, id)
	if err != nil {
		logger.Errorf("an error occurred while trying to verify phone token.\nThe error: %s", err)
		return err, false
	}
	if purpose == "login2fa" {
		tokenExpiry := time.Unix(acc.LoginPhoneExpiry, 0)
		now := time.Now()

		if int64(tokenExpiry.Sub(now).Seconds()) < 0 {
			logger.Errorf("phone token expired")
			return errors.InternalServerError("phoneTokenExpired"), false
		}

		i, _ := strconv.Atoi(token)

		if i != acc.LoginPhoneToken {
			return nil, false
		}
	}

	if purpose == "verification" {
		tokenExpiry := time.Unix(acc.ConfirmPhoneExpiry, 0)
		now := time.Now()

		if int64(tokenExpiry.Sub(now).Seconds()) < 0 {
			logger.Errorf("phone token expired")
			return errors.InternalServerError("phoneTokenExpired"), false
		}

		i, _ := strconv.Atoi(token)

		if i != acc.ConfirmPhoneToken {
			return nil, false
		}

		acc.ConfirmedPhone = 1
		updateErr := s.repo.AccountUpdate(ctx, acc.Accounts)
		if updateErr != nil {
			logger.Errorf("an error occurred while trying to update confirmed phone status after veri.\n" +
				"The error: %s, err")
		}
	}

	return nil, true
}

func (s service) set2FA(ctx context.Context, id, email, phone, Type string) error {
	logger := s.logger.With(ctx, "account", id)
	acc, err := s.getAccountById(ctx, id)
	if err != nil {
		logger.Errorf("an error occurred while trying to verify phone token.\nThe error: %s", err)
		return err
	}
	if Type == "phone" {
		if acc.ConfirmedPhone != 1 {
			logger.Errorf("phone number has not been verified\nThe error: %s, err")
			return err
		}

		setAcct, err := s.getSettingsById(ctx, id)
		if err != nil {
			if err == sql.ErrNoRows {
				if err := s.repo.CreateSettings(ctx, entity.Settings{
					AccountId:  acc.Id,
					TwofaPhone: 1,
				}); err != nil {
					logger.Errorf("could not insert into settings row\nThe error: %s", err)
					return err
				}
			}
			logger.Errorf("an error occurred while trying to get settings\nThe error: %s", err)
		} else {
			setAcct.TwofaPhone = 1
			err := s.repo.UpdateSettings(ctx, setAcct.Settings)
			if err != nil {
				logger.Errorf("an error occurred while trying to update settings phone ver. The error: %s", err)
			}
		}
		t, _ := template.ParseFiles("internal/email/securityAlertEmailTemplate.gohtml")
		var body bytes.Buffer
		_ = t.Execute(&body, struct {
			Message string
		}{
			Message: "2FA has been enabled on your mobile number: " + phone + ". \nThis would be active if google authenticator and email 2FA is not activated",
		})
		contentToString := string(body.Bytes())
		sendmailErr := s.emailService.SendEmail(email, "2FA Authorised", contentToString)
		if sendmailErr != nil {
			logger.Errorf("an error occurred while trying to send email.\nThe error: %s", sendmailErr)
			return sendmailErr
		}
	}

	if Type == "email" {
		if acc.ConfirmedEmail != 1 {
			logger.Errorf("email has not been verified\nThe error: %s", err)
			return errors.InternalServerError("emailFaulty")
		}

		setAcct, err := s.getSettingsById(ctx, id)
		if err != nil {
			if err == sql.ErrNoRows {
				if err := s.repo.CreateSettings(ctx, entity.Settings{
					AccountId:  acc.Id,
					TwofaEmail: 1,
				}); err != nil {
					logger.Errorf("could not insert into settings row\nThe error: %s", err)
					return err
				}
			}
			logger.Errorf("an error occurred while trying to get settings\nThe error: %s", err)
		} else {
			setAcct.TwofaEmail = 1
			err := s.repo.UpdateSettings(ctx, setAcct.Settings)
			if err != nil {
				logger.Errorf("an error occurred while trying to update settings email ver.The error: %s", err)
				return err
			}
		}
		t, _ := template.ParseFiles("internal/email/securityAlertEmailTemplate.gohtml")
		var body bytes.Buffer
		_ = t.Execute(&body, struct {
			Message string
		}{
			Message: "2FA has been enabled on your email: " + email + ". \nThis would be active if google authenticator 2FA is not activated",
		})
		contentToString := string(body.Bytes())
		sendmailErr := s.emailService.SendEmail(email, "2FA Authorised", contentToString)
		if sendmailErr != nil {
			logger.Errorf("an error occurred while trying to send email.\nThe error: %s", sendmailErr)
			return sendmailErr
		}
	}
	return nil
}

func (s service) setupTOTP(ctx context.Context, email string) (string, []byte, error) {
	logger := s.logger.With(ctx, "account", email)
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Monitri",
		AccountName: email,
	})
	if err != nil {
		logger.Errorf("an error occurred while trying to generate totp key. The error: %s", err)
	}
	var buf bytes.Buffer
	img, errr := key.Image(200, 200)
	if errr != nil {
		logger.Errorf("an error occurred while trying to generate totp key. The error: %s", errr)
	}
	_ = png.Encode(&buf, img)
	return key.Secret(), buf.Bytes(), nil
}

func (s service) validateTOTPFirstTime(ctx context.Context, id, email, passcode, secret string) bool {
	logger := s.logger.With(ctx, "account", id)
	acc, err := s.getAccountById(ctx, id)
	if err != nil {
		logger.Errorf("an error occurred while trying to fetch user acc. The error: %s", err)
	}
	ok := totp.Validate(passcode, secret)
	if !ok {
		logger.Errorf("passcode=%s\n secret=%s", passcode, secret)
		return false
	}
	acc.TotpSecret = secret
	acc.UpdatedAt = time.Now()
	setAcct, err := s.getSettingsById(ctx, id)
	if err != nil {
		if err == sql.ErrNoRows {
			if errr := s.repo.updateAccountAndSettingsTableTrans(ctx, acc.Accounts, entity.Settings{
				AccountId:       acc.Id,
				TwofaGoogleAuth: 1,
			}, "insert"); errr != nil {
				logger.Errorf("an error occurred while trying to update totp secret for the acc. The error: %s", errr)
				return false
			}
		}
		logger.Errorf("an error occurred while trying to get settings\nThe error: %s", err)
	} else {
		setAcct.TwofaGoogleAuth = 1
		if errr := s.repo.updateAccountAndSettingsTableTrans(ctx, acc.Accounts, setAcct.Settings, "update"); errr != nil {
			logger.Errorf("an error occurred while trying to update settings email ver.The error: %s", errr)
			return false
		}
	}

	t, _ := template.ParseFiles("internal/email/securityAlertEmailTemplate.gohtml")
	var body bytes.Buffer
	_ = t.Execute(&body, struct {
		Message string
	}{
		Message: "You just activated Google Authenticator 2FA on your account!.",
	})
	contentToString := string(body.Bytes())
	sendmailErr := s.emailService.SendEmail(email, "2FA Authorised", contentToString)
	if sendmailErr != nil {
		logger.Errorf("an error occurred while trying to send email.\nThe error: %s", sendmailErr)
		return false
	}
	return true
}

func (s service) validateTOTP(ctx context.Context, passcode, secret string) bool {
	logger := s.logger.With(ctx, "account", secret)
	if ok := totp.Validate(passcode, secret); !ok {
		logger.Errorf("passcode validation failed.")
		return false
	}
	return true
}

func (s service) getBanks(ctx context.Context) ([]byte, error) {
	logger := s.logger.With(ctx)
	u, _ := url.ParseRequestURI(s.PaystackUrl)
	urlToString := u.String()

	request, _ := http.NewRequest(http.MethodGet, urlToString+"/bank", nil)
	request.Header.Add("Authorization", "Bearer "+s.PSec)

	resp, err := http.DefaultClient.Do(request)
	if err != nil {
		logger.Errorf("Error:", err)
		return nil, err
	}
	if resp.StatusCode == 200 {
		dataa, _ := ioutil.ReadAll(resp.Body)
		defer resp.Body.Close()

		return dataa, nil
	}

	return nil, errors.InternalServerError("An unhandled error occurred")
}

func (s service) verifyBankAcctNo(ctx context.Context, bankCode, bankAcctNo string) ([]byte, bool, error) {
	logger := s.logger.With(ctx)

	data := url.Values{}
	data.Set("account_number", bankAcctNo)
	data.Set("bank_code", bankCode)

	u, _ := url.ParseRequestURI(s.PaystackUrl)
	urlToString := u.String()

	request, _ := http.NewRequest(http.MethodGet, urlToString+"/bank/resolve", strings.NewReader(data.Encode()))
	request.Header.Add("Authorization", "Bearer "+s.PSec)

	resp, err := http.DefaultClient.Do(request)
	if err != nil {
		logger.Errorf("Error:", err)
		return nil, false, err
	}
	if resp.StatusCode == 200 {
		data, _ := ioutil.ReadAll(resp.Body)
		defer resp.Body.Close()

		return data, true, nil
	}

	return nil, false, errors.InternalServerError("An unhandled error occurred")
}

//func (s service) setBankDetails(ctx context.Context, email, bankName string, req SetBankDetailsRequest) error {
//	logger := s.logger.With(ctx, "account", email)
//
//	_, ok, err := s.verifyBankAcctNo(ctx, req.BankCode, req.AccountNumber)
//	if !ok {
//		logger.Error("An error occurred while trying to verify the account number")
//		return err
//	}
//
//	_, _, ok = s.completedVerification(ctx, email)
//	if !ok {
//		logger.Error("Must verify email, phone and update profile before you continue")
//		return errors.InternalServerError("Must verify email, phone and update profile before you continue")
//	}
//
//	acct, err := s.getAccountByEmail(ctx, email)
//	if err != nil {
//		logger.Errorf("An error occurred while trying to get the account with email. The error is: %s", err)
//		return err
//	}
//	req.Type = "nuban"
//	req.Name = acct.Lastname + " " + acct.Firstname
//
//	b, err := json.Marshal(req)
//	if err != nil {
//		logger.Errorf("An error occurred while trying to convert the request struct to json. Error msg is: %s", err)
//		return err
//	}
//
//	u, _ := url.ParseRequestURI(s.PaystackUrl)
//	urlToString := u.String()
//
//	request, _ := http.NewRequest(http.MethodPost, urlToString+"/transferrecipient", bytes.NewBuffer(b))
//	request.Header.Add("Authorization", "Bearer "+s.PSec)
//	request.Header.Add("Content-Type", "application/json")
//
//	resp, err := http.DefaultClient.Do(request)
//	if err != nil {
//		logger.Errorf("Error:", err)
//		return err
//	}
//	if resp.StatusCode == 200 {
//		data, _ := ioutil.ReadAll(resp.Body)
//		defer resp.Body.Close()
//
//		var responsePayload *PaystackGeneralResponse
//		_ = json.Unmarshal(data, &responsePayload)
//
//		acct.BankCode = responsePayload.Data.Details["bank_code"].(string)
//		acct.BankAccountNo = responsePayload.Data.Details["account_number"].(string)
//	}
//}

//-------------------------------------------------TRANSACTION FUNCTIONS------------------------------------------------

func (s service) getTransactionByTransRef(ctx context.Context, transRef string) (Transaction, error) {
	transaction, err := s.repo.GetTransactionByTransRef(ctx, transRef)
	if err != nil {
		return Transaction{}, err
	}
	return Transaction{transaction}, err
}

//func (s service) getLatestTransactionInfo(ctx context.Context, accountId string) (Transaction, error) {
//	logger := s.logger.With(ctx, "account", accountId)
//	trans, err := s.repo.GetLatestTransaction(ctx, accountId)
//	if err != nil {
//		if err == sql.ErrNoRows {
//			return Transaction{}, err
//		}
//		logger.Errorf("an error occurred while trying to get latest transaction\nThe error: %s", err)
//	}
//	return Transaction{trans}, nil
//}

func (s service) createTrans(ctx context.Context, accId, transRef string) error {
	//.Format(time.RFC3339),
	logger := s.logger.With(ctx, "transaction", accId)
	id := entity.GenerateID()
	err := s.repo.TransactionCreate(ctx, entity.Transactions{
		Id:            id,
		AccountId:     accId,
		TransactionId: transRef,
		Status:        "pending",
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	})
	if err != nil {
		logger.Errorf("error occurred while trying to create a transaction for the user %s", id)
		return err
	}
	return nil
}

func (s service) updateTrans(ctx context.Context, acctId, transRef, status, transType, currency, requestPayload string, amount, currentBalance int) error {
	logger := s.logger.With(ctx, "transaction", transRef)
	trans, err := s.getTransactionByTransRef(ctx, transRef)
	if err != nil {
		logger.Errorf("error occurred while trying to fetch a transaction with the ref %s", transRef)
		return err
	}
	trans.Amount = amount
	trans.Status = status
	trans.TransactionType = transType
	trans.Currency = currency
	trans.PaystackPayload = requestPayload

	acct, err := s.getAccountById(ctx, acctId)
	if err != nil {
		logger.Errorf("error occurred while trying to fetch the account that has the transaction with the ref %s", transRef)
		return err
	}
	acct.CurrentBalance = currentBalance
	updateErr := s.repo.updateAccountAndTransactionTableTrans(ctx, acct.Accounts, trans.Transactions)
	if updateErr != nil {
		fmt.Println(updateErr)
		logger.Errorf("error occurred while trying to update a transaction with transaction ref %s", transRef)
		return updateErr
	}
	return nil
}

func (s service) verifyOnPaystack(transRef string) bool {
	u, _ := url.ParseRequestURI(s.PaystackUrl)
	urlToString := u.String()

	req, _ := http.NewRequest(http.MethodGet, urlToString+"/transaction/verify/"+transRef, nil)
	req.Header.Add("Authorization", "Bearer "+s.PSec)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.logger.Errorf("Error:", err)
	}

	if resp.StatusCode == 200 {
		// read response body
		dataa, _ := ioutil.ReadAll(resp.Body)
		defer resp.Body.Close()
		var responsePayload *VerifyPaymentResponsePayload
		_ = json.Unmarshal(dataa, &responsePayload)
		if responsePayload.Data.Status == "success" {
			return true
		}
	}
	return false
}

func (s service) initiateTransaction(ctx context.Context, id string, req InitiateTransactionRequest) ([]byte, error) {
	logger := s.logger.With(ctx, "account", req.Email)
	if err := req.validate(); err != nil {
		fmt.Printf("valdation error is: %s", err)
		return nil, err
	}
	RandomCrypto, _ := rand.Prime(rand.Reader, 20)
	req.Reference = strconv.Itoa(int(time.Now().Unix())) + "-" + strconv.Itoa(int(RandomCrypto.Int64()))

	u, _ := url.ParseRequestURI(s.PaystackUrl)
	urlToString := u.String()

	b, err := json.Marshal(req)
	if err != nil {
		logger.Errorf("An error occurred while trying to convert the request struct to json. Error msg is: %s", err)
		return nil, err
	}

	request, _ := http.NewRequest(http.MethodPost, urlToString+"/transaction/initialize", bytes.NewBuffer(b))
	request.Header.Add("Authorization", "Bearer "+s.PSec)
	request.Header.Add("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(request)
	if err != nil {
		logger.Errorf("Error:", err)
		return nil, err
	}
	if resp.StatusCode == 200 {
		dataa, _ := ioutil.ReadAll(resp.Body)
		defer resp.Body.Close()

		var responsePayload *PaystackGeneralResponse
		_ = json.Unmarshal(dataa, &responsePayload)
		respJson, err := json.Marshal(responsePayload)
		if err != nil {
			logger.Errorf("An error occurred while trying to convert the response struct to json. Error msg is: %s", err)
			return nil, err
		}
		if err := s.createTrans(ctx, id, responsePayload.Data.Reference); err != nil {
			logger.Errorf("An error occurred while trying to write transaction to DB. Error msg is: %s", err)
			return nil, err
		}
		return respJson, nil
	}
	return nil, errors.BadRequest("")
}

//----------------------------------------------------REDIS FUNCTIONS---------------------------------------------------

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

func (s service) checkIfKeyExist(conn redis.Conn, key string) (string, error) {
	val, err := s.repo.GetRedisKey(conn, key)
	return val, err
}

func (s service) logOut(ctx context.Context, conn redis.Conn, keys ...string) error {
	logger := s.logger.With(ctx, "accessUUID", keys)
	_ = s.repo.DeleteRedisKeys(conn, keys...)
	logger.Infof("deleted redis key %s", keys)

	return nil
}

//todo remember to increase the time to 10 minutes (600sec)
//func (s service) flagIP(conn redis.Conn, ip string) error {
//	err := s.repo.SetRedisKey(conn, 180, ip, "malicious user")
//	if err != nil {
//		s.logger.Errorf("an error occurred while trying to store the flaggedIp in redis. The error:%s", err)
//	}
//	return nil
//}
