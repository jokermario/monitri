package accounts

import (
	"encoding/hex"
	"encoding/json"
	errors2 "errors"
	routing "github.com/go-ozzo/ozzo-routing/v2"
	"github.com/gomodule/redigo/redis"
	"github.com/jokermario/monitri/internal/errors"
	"github.com/jokermario/monitri/pkg/log"
	"github.com/jokermario/monitri/pkg/pagination"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"
)

func RegisterHandlers(r *routing.RouteGroup, service2 Service, AccessTokenSigningKey,
	RefreshTokenSigningKey string, logger log.Logger, redisConn redis.Conn) {
	res := resource{service2, logger, redisConn}

	authHandler := Handler(AccessTokenSigningKey, RefreshTokenSigningKey, service2, redisConn)
	r.Use(RateHandler())

	r.Get("/ping", res.healthCheck)
	r.Post("/generate/token", res.login(logger))
	r.Post("/generate/mobile2fa/token", res.LoginWithMobile2FA(logger))
	r.Post("/generate/email2fa/token", res.LoginWithEmail2FA(logger))
	r.Post("/account/email/token/<purpose>", res.sendEmailVeriToken)
	r.Post("/new/account", res.createAccount(logger))
	r.Post("/transaction/webhook", res.paystackWebhookForTransaction(logger))

	r.Use(authHandler)

	//r.Get("/account/<id>", res.getAccountById)
	//r.Get("/account/<email>", res.getByEmail)
	//r.Get("/user/all")
	//r.Put("")
	//--------------------------------------------------ACCOUNT ENDPOINTS---------------------------------------------------
	r.Post("/account/profile/update", res.updateProfile)
	r.Delete("/account/delete", res.deleteById)
	r.Post("/account/logout", res.logout)
	r.Post("/refresh/token", res.refreshToken)
	r.Post("/account/phone/token", res.sendPhoneVeriToken)
	r.Post("/account/verify/email/<token>/<purpose>", res.verifyEmailToken)
	r.Post("/account/verify/phone/<token>/<purpose>", res.verifyPhoneToken)
	r.Post("/account/change/password", res.changePassword)
	r.Post("/account/auth/totp/setup", res.setupTOTP)
	r.Post("/account/auth/totp/initial/validate/<secret>/<passcode>", res.validateTOTPFirstTime)
	r.Post("/account/auth/totp/validate/<passcode>", res.validateTOTP)
	r.Post("/account/auth/setup2fa/email", res.setup2FA)
	r.Post("/account/verified", res.checkAccountVerificationStatus)
	r.Post("/list/banks", res.getNigerianBanks)
	r.Post("/verify/bankaccount/<bankCode>/<acctNo>", res.verifyBankAccountNumber)
	r.Post("/get/2fatype", res.get2FAType)
	r.Post("/account/unset2fa/<passcode>/<authType>", res.unset2FA)
	r.Post("/account/bankdetails/<passcode>/<authType>", res.setBankDetails)

	//-------------------------------------------------TRANSACTION ENDPOINTS------------------------------------------------
	r.Post("/transaction/initialize", res.initiatedTransaction)
}

type resource struct {
	service   Service
	logger    log.Logger
	redisConn redis.Conn
}

func (r resource) healthCheck(rc *routing.Context) error {
	return rc.WriteWithStatus("Live", http.StatusOK)
}

func (r resource) getNigerianBanks(rc *routing.Context) error {
	b, err := r.service.getBanks(rc.Request.Context())
	if err != nil {
		return errors.InternalServerError("An error occurred")
	}
	type responseData struct {
		Status  string `json:"status"`
		Message string `json:"message"`
		Data    []struct {
			Name      string      `json:"name,omitempty"`
			Slug      string      `json:"slug,omitempty"`
			Code      string      `json:"code,omitempty"`
			Longcode  string      `json:"longcode,omitempty"`
			Gateway   string      `json:"-"`
			Active    bool        `json:"active,omitempty"`
			IsDeleted interface{} `json:"-"`
			Id        int         `json:"-"`
			CreatedAt string      `json:"-"`
			UpdatedAt string      `json:"-"`
		} `json:"data"`
	}
	var data *responseData
	_ = json.Unmarshal(b, &data)
	return rc.WriteWithStatus(data, http.StatusOK)
}

func (r resource) verifyBankAccountNumber(rc *routing.Context) error {
	b, _, err := r.service.verifyBankAcctNo(rc.Request.Context(), rc.Param("bankCode"), rc.Param("acctNo"))
	if err != nil {
		return errors.InternalServerError("An error occurred")
	}
	type responseData struct {
		Status  bool   `json:"status"`
		Message string `json:"message"`
		Data    struct {
			AccountNumber string `json:"account_number,omitempty"`
			AccountName   string `json:"account_name,omitempty"`
		} `json:"data"`
	}
	var data *responseData
	_ = json.Unmarshal(b, &data)
	return rc.WriteWithStatus(data, http.StatusOK)
}

func (r resource) get2FAType(rc *routing.Context) error {
	identity := CurrentAccount(rc.Request.Context())
	authType, err := r.service.get2FAType(rc.Request.Context(), identity.GetID())
	if err != nil {
		if err == errors.InternalServerError("2FANotSet"){
			return rc.WriteWithStatus(struct {
				Status  string `json:"status"`
				Message string `json:"message"`
			}{
				"failed",
				"No 2FA has been set for this account",
			}, http.StatusInternalServerError)
		}else {
			return errors.InternalServerError("An error occurred")
		}
	}
	type data struct {
		AuthType string `json:"auth_type"`
	}
	return rc.WriteWithStatus(struct {
		Status  string `json:"status"`
		Message string `json:"message"`
		Data    data   `json:"data"`
	}{
		"success",
		"The auth type has been retrieved",
		data{
			authType,
		},
	}, http.StatusOK)
}

func (r resource) unset2FA(rc *routing.Context) error {
	identity := CurrentAccount(rc.Request.Context())
	err := r.service.unset2FA(rc.Request.Context(), identity.GetID(), identity.GetEmail(), rc.Param("passcode"), rc.Param("authType"))
	if err != nil {
		if err == errors.InternalServerError("settingsNotExist"){
			return rc.WriteWithStatus(struct {
				Status  string `json:"status"`
				Message string `json:"message"`
			}{
				"failed",
				"2FA has not been set",
			}, http.StatusInternalServerError)
		}else if err == errors.InternalServerError("passcodeErr"){
			return rc.WriteWithStatus(struct {
				Status  string `json:"status"`
				Message string `json:"message"`
			}{
				"failed",
				"The passcode is not valid",
			}, http.StatusInternalServerError)
		}else if err == errors.InternalServerError("TokenInvalid") {
			return rc.WriteWithStatus(struct {
				Status  string `json:"status"`
				Message string `json:"message"`
			}{
				"failed",
				"The token is invalid",
			}, http.StatusInternalServerError)
		}else {
			return errors.InternalServerError("An error occurred")
		}
	}

	return rc.WriteWithStatus(struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	}{
		"success",
		"The 2FA has been unset successfully",
	}, http.StatusOK)
}

func (r resource) setBankDetails(rc *routing.Context) error {
	var input SetBankDetailsRequest

	if err := rc.Read(&input); err != nil {
		return errors.BadRequest("invalid request. Cannot read the body")
	}

	identity := CurrentAccount(rc.Request.Context())
	err := r.service.setBankDetails(rc.Request.Context(), identity.GetID(), identity.GetEmail(), rc.Param("passcode"), rc.Param("authType"), input)
	if err != nil {
		if err == errors.InternalServerError("settingsNotExist"){
			return rc.WriteWithStatus(struct {
				Status  string `json:"status"`
				Message string `json:"message"`
			}{
				"failed",
				"2FA has not been set",
			}, http.StatusInternalServerError)
		}else if err == errors.InternalServerError("passcodeErr"){
			return rc.WriteWithStatus(struct {
				Status  string `json:"status"`
				Message string `json:"message"`
			}{
				"failed",
				"The passcode is not valid",
			}, http.StatusInternalServerError)
		}else if err == errors.InternalServerError("TokenInvalid") {
			return rc.WriteWithStatus(struct {
				Status  string `json:"status"`
				Message string `json:"message"`
			}{
				"failed",
				"The token is invalid",
			}, http.StatusInternalServerError)
		}else {
			return errors.InternalServerError("An error occurred")
		}
	}

	return rc.WriteWithStatus(struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	}{
		"success",
		"Bank details have been set successfully",
	}, http.StatusOK)
}

//-------------------------------------------------------ACCOUNT--------------------------------------------------------

// login returns a handler that handles accounts login request.
func (r resource) login(logger log.Logger) routing.Handler {
	return func(c *routing.Context) error {
		logger := logger.With(c.Request.Context())
		var req LoginRequest

		if err := c.Read(&req); err != nil {
			logger.Errorf("invalid request: %v", err)
			return errors.BadRequest("")
		}
		TokenDetails, loginErr, additionalSec := r.service.login(c.Request.Context(), req)
		if loginErr != nil {
			logger.Errorf("invalid request: %v", loginErr)
			return loginErr
		}
		//encrypt access and refresh token
		encAccessToken, err := r.service.aesEncrypt(TokenDetails.AccessToken)
		if err != nil {
			return errors.InternalServerError("")
		}
		encRefreshToken, err := r.service.aesEncrypt(TokenDetails.RefreshToken)
		if err != nil {
			return errors.InternalServerError("")
		}
		if additionalSec != "" {
			return c.Write(struct {
				AdditionalSecurity string `json:"additional_security,omitempty"`
			}{additionalSec})
		} else {
			redisErr := r.service.storeAuthKeys(r.redisConn, req.Email, TokenDetails)
			if redisErr != nil {
				return redisErr
			}
			ip, _, err := net.SplitHostPort(c.Request.RemoteAddr)
			if err != nil {
				return errors.InternalServerError("")
			}
			r.service.sendLoginNotifEmail(c.Request.Context(), req.Email, time.Now().Format(time.RFC3339), ip, c.Request.UserAgent())

			err, mssg, _ := r.service.completedVerification(c.Request.Context(), req.Email)
			var vComp string
			if mssg != nil && err != nil {
				vComp = "no"
			} else {
				vComp = "yes"
			}

			type data struct {
				//TokenType    string `json:"token_type"`
				Email                 string `json:"email"`
				CompletedVerification string `json:"completed_verification"`
				AccessToken           string `json:"access_token"`
				ExpiryTime            int64  `json:"expires"`
				RefreshToken          string `json:"refresh_token"`
			}
			return c.Write(struct {
				Status  string `json:"status"`
				Message string `json:"message"`
				Data    data   `json:"data,omitempty"`
			}{"success", "tokens generated", data{req.Email, vComp, hex.EncodeToString(encAccessToken), TokenDetails.AtExpires,
				hex.EncodeToString(encRefreshToken)}})
		}
	}
}

func (r resource) LoginWithMobile2FA(logger log.Logger) routing.Handler {
	return func(c *routing.Context) error {
		logger := logger.With(c.Request.Context())
		var req AdditionalSecLoginRequest

		if err := c.Read(&req); err != nil {
			logger.Errorf("invalid request: %v", err)
			return errors.BadRequest("")
		}
		TokenDetails, loginErr := r.service.LoginWithMobile2FA(c.Request.Context(), req)
		if loginErr != nil {
			logger.Errorf("invalid request: %v", loginErr)
			return loginErr
		}
		//encrypt access and refresh token
		encAccessToken, err := r.service.aesEncrypt(TokenDetails.AccessToken)
		if err != nil {
			return errors.InternalServerError("")
		}
		encRefreshToken, err := r.service.aesEncrypt(TokenDetails.RefreshToken)
		if err != nil {
			return errors.InternalServerError("")
		}
		redisErr := r.service.storeAuthKeys(r.redisConn, req.Email, TokenDetails)
		if redisErr != nil {
			return redisErr
		}
		ip, _, err := net.SplitHostPort(c.Request.RemoteAddr)
		if err != nil {
			return errors.InternalServerError("")
		}
		r.service.sendLoginNotifEmail(c.Request.Context(), req.Email, time.Now().Format(time.RFC3339), ip, c.Request.UserAgent())
		err, mssg, _ := r.service.completedVerification(c.Request.Context(), req.Email)
		var vComp string
		if mssg != nil && err != nil {
			vComp = "no"
		} else {
			vComp = "yes"
		}
		type data struct {
			//TokenType    string `json:"token_type"`
			Email                 string `json:"email"`
			CompletedVerification string `json:"completed_verification"`
			AccessToken           string `json:"access_token"`
			ExpiryTime            int64  `json:"expires"`
			RefreshToken          string `json:"refresh_token"`
		}
		return c.Write(struct {
			Status  string `json:"status"`
			Message string `json:"message"`
			Data    data   `json:"data,omitempty"`
		}{"success", "tokens generated", data{req.Email, vComp, hex.EncodeToString(encAccessToken), TokenDetails.AtExpires,
			hex.EncodeToString(encRefreshToken)}})
	}
}

func (r resource) LoginWithEmail2FA(logger log.Logger) routing.Handler {
	return func(c *routing.Context) error {
		logger := logger.With(c.Request.Context())
		var req AdditionalSecLoginRequest

		if err := c.Read(&req); err != nil {
			logger.Errorf("invalid request: %v", err)
			return errors.BadRequest("")
		}
		TokenDetails, loginErr := r.service.loginWithEmail2FA(c.Request.Context(), req)
		if loginErr != nil {
			logger.Errorf("invalid request: %v", loginErr)
			return loginErr
		}
		//encrypt access and refresh token
		encAccessToken, err := r.service.aesEncrypt(TokenDetails.AccessToken)
		if err != nil {
			return errors.InternalServerError("")
		}
		encRefreshToken, err := r.service.aesEncrypt(TokenDetails.RefreshToken)
		if err != nil {
			return errors.InternalServerError("")
		}
		redisErr := r.service.storeAuthKeys(r.redisConn, req.Email, TokenDetails)
		if redisErr != nil {
			return redisErr
		}
		ip, _, err := net.SplitHostPort(c.Request.RemoteAddr)
		if err != nil {
			return errors.InternalServerError("")
		}
		r.service.sendLoginNotifEmail(c.Request.Context(), req.Email, time.Now().Format(time.RFC3339), ip, c.Request.UserAgent())

		err, mssg, _ := r.service.completedVerification(c.Request.Context(), req.Email)
		var vComp string
		if mssg != nil && err != nil {
			vComp = "no"
		} else {
			vComp = "yes"
		}

		type data struct {
			//TokenType    string `json:"token_type"`
			Email                 string `json:"email"`
			CompletedVerification string `json:"completed_verification"`
			AccessToken           string `json:"access_token"`
			ExpiryTime            int64  `json:"expires"`
			RefreshToken          string `json:"refresh_token"`
		}
		return c.Write(struct {
			Status  string `json:"status"`
			Message string `json:"message"`
			Data    data   `json:"data,omitempty"`
		}{"success", "tokens generated", data{req.Email, vComp, hex.EncodeToString(encAccessToken), TokenDetails.AtExpires,
			hex.EncodeToString(encRefreshToken)}})
	}
}

//func (r resource) LoginWithPhone2FA(logger log.Logger) routing.Handler {
//	return func(c *routing.Context) error {
//		logger := logger.With(c.Request.Context())
//		var req AdditionalSecLoginRequest
//
//		if err := c.Read(&req); err != nil {
//			logger.Errorf("invalid request: %v", err)
//			return errors.BadRequest("")
//		}
//		TokenDetails, loginErr := r.service.loginWithPhone2FA(c.Request.Context(), req)
//		if loginErr != nil {
//			logger.Errorf("invalid request: %v", loginErr)
//			return loginErr
//		}
//		//encrypt access and refresh token
//		encAccessToken, err := r.service.aesEncrypt(TokenDetails.AccessToken)
//		if err != nil {
//			return errors.InternalServerError("")
//		}
//		encRefreshToken, err := r.service.aesEncrypt(TokenDetails.RefreshToken)
//		if err != nil {
//			return errors.InternalServerError("")
//		}
//
//		redisErr := r.service.storeAuthKeys(r.redisConn, req.Email, TokenDetails)
//		if redisErr != nil {
//			return redisErr
//		}
//		ip, _, err := net.SplitHostPort(c.Request.RemoteAddr)
//		if err != nil {
//			return errors.InternalServerError("")
//		}
//		r.service.sendLoginNotifEmail(c.Request.Context(), req.Email, time.Now().Format(time.RFC3339), ip, c.Request.UserAgent())
//
//		err, mssg, _ := r.service.completedVerification(c.Request.Context(), req.Email)
//		var vComp string
//		if mssg != nil && err != nil {
//			vComp = "no"
//		} else {
//			vComp = "yes"
//		}
//
//		type data struct {
//			//TokenType    string `json:"token_type"`
//			Email                 string `json:"email"`
//			CompletedVerification string `json:"completed_verification"`
//			AccessToken           string `json:"access_token"`
//			ExpiryTime            int64  `json:"expires"`
//			RefreshToken          string `json:"refresh_token"`
//		}
//		return c.Write(struct {
//			Status  string `json:"status"`
//			Message string `json:"message"`
//			Data    data   `json:"data,omitempty"`
//		}{"success", "tokens generated", data{req.Email, vComp, hex.EncodeToString(encAccessToken), TokenDetails.AtExpires,
//			hex.EncodeToString(encRefreshToken)}})
//	}
//}

func (r resource) createAccount(logger log.Logger) routing.Handler {
	return func(context *routing.Context) error {
		var input CreateAccountsRequest
		if err := context.Read(&input); err != nil {
			logger.With(context.Request.Context()).Errorf("problems occurred reading the payload: %v", err)
			return errors.BadRequest("")
		}

		err := r.service.createAccount(context.Request.Context(), input)
		if err != nil {
			logger.With(context.Request.Context()).Errorf("problems occurred while creating an account: %v", err)
			return context.WriteWithStatus(errors.InternalServerError("problems occurred while creating an account"),
				http.StatusBadRequest)
		}
		return context.WriteWithStatus(struct {
			Status  string `json:"status"`
			Message string `json:"message"`
		}{"success", "Account created successfully"}, http.StatusOK)
	}
}

func (r resource) getById(rc *routing.Context) error {
	account, err := r.service.getAccountById(rc.Request.Context(), rc.Param("id"))
	if err != nil {
		return err
	}
	return rc.WriteWithStatus(account, http.StatusOK)
}

func (r resource) getByEmail(rc *routing.Context) error {
	account, err := r.service.getAccountByEmail(rc.Request.Context(), rc.Param("email"))
	if err != nil {
		return err
	}
	return rc.WriteWithStatus(account, http.StatusOK)
}

func (r resource) updateProfile(rc *routing.Context) error {
	var input UpdateAccountRequest
	if err := rc.Read(&input); err != nil {
		r.logger.With(rc.Request.Context()).Error(err)
		return errors.BadRequest("cannot be read")
	}

	identity := CurrentAccount(rc.Request.Context())
	account, err := r.service.updateProfile(rc.Request.Context(), identity.GetID(), input)
	if err != nil {
		r.logger.With(rc.Request.Context()).Error(err)
		return err
	}

	return rc.WriteWithStatus(account, http.StatusOK)
}

func (r resource) getAccounts(rc *routing.Context) error {
	ctx := rc.Request.Context()
	count, err := r.service.count(ctx)
	if err != nil {
		r.logger.With(ctx).Error(err)
		return err
	}
	pages := pagination.NewFromRequest(rc.Request, count)
	account, err := r.service.getAccounts(ctx, pages.Offset(), pages.Limit())
	if err != nil {
		r.logger.With(ctx).Error(err)
		return err
	}
	pages.Items = account
	return rc.WriteWithStatus(pages, http.StatusOK)
}

func (r resource) deleteById(rc *routing.Context) error {
	identity := CurrentAccount(rc.Request.Context())
	if err := r.service.deleteById(rc.Request.Context(), identity.GetID()); err != nil {
		r.logger.With(rc.Request.Context()).Error(err)
		return err
	}
	return rc.WriteWithStatus(struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	}{"success", "deleted successfully"}, http.StatusOK)
}

func (r resource) logout(rc *routing.Context) error {
	identity := CurrentAccount(rc.Request.Context())
	//deletes the refresh token from redis
	_ = r.service.logOut(rc.Request.Context(), r.redisConn, identity.GetAccessID())
	return rc.WriteWithStatus(struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	}{"success", "logged out successfully"}, http.StatusOK)
}

func (r resource) refreshToken(rc *routing.Context) error {
	identity := CurrentAccount(rc.Request.Context())
	userIdentity := r.service.getAccountIdEmailPhone(rc.Request.Context(), identity.GetID())
	if userIdentity == nil {
		return errors.BadRequest("The refresh token is not valid")
	}
	tokenDetails, err := r.service.generateTokens(userIdentity)
	if err != nil {
		return errors.InternalServerError("a problem occurred while trying to generate a new access token")
	}
	TokenDetails, refErr := r.service.refreshToken(userIdentity, r.redisConn, identity.GetEmail(), tokenDetails)
	if refErr != nil {
		return errors.InternalServerError("an error occurred while storing the refresh token")
	}
	//encrypt access and refresh token
	encAccessToken, err := r.service.aesEncrypt(TokenDetails.AccessToken)
	if err != nil {
		return errors.InternalServerError("")
	}
	encRefreshToken, err := r.service.aesEncrypt(TokenDetails.RefreshToken)
	if err != nil {
		return errors.InternalServerError("")
	}
	//deletes the refresh token from redis
	_ = r.service.logOut(rc.Request.Context(), r.redisConn, identity.GetRefreshID())

	err, mssg, _ := r.service.completedVerification(rc.Request.Context(), identity.GetEmail())
	var vComp string
	if mssg != nil && err != nil {
		vComp = "no"
	} else {
		vComp = "yes"
	}

	type data struct {
		//TokenType    string `json:"token_type"`
		Email                 string `json:"email"`
		CompletedVerification string `json:"completed_verification"`
		AccessToken           string `json:"access_token"`
		ExpiryTime            int64  `json:"expires"`
		RefreshToken          string `json:"refresh_token"`
	}
	return rc.Write(struct {
		Status  string `json:"status"`
		Message string `json:"message"`
		Data    data   `json:"data,omitempty"`
	}{"success", "tokens generated", data{identity.GetEmail(), vComp, hex.EncodeToString(encAccessToken), TokenDetails.AtExpires,
		hex.EncodeToString(encRefreshToken)}})
}

func (r resource) sendEmailVeriToken(rc *routing.Context) error {
	var req LoginRequest

	if err := rc.Read(&req); err != nil {
		return errors.BadRequest("invalid request. Cannot read the request")
	}

	err := r.service.generateAndSendEmailToken(rc.Request.Context(), req, rc.Param("purpose"))
	if err != nil {
		return errors.InternalServerError("an error occurred while generating and sending token")
	}
	return rc.WriteWithStatus(struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	}{"success", "sent successfully"}, http.StatusOK)
}

func (r resource) sendPhoneVeriToken(rc *routing.Context) error {
	identity := CurrentAccount(rc.Request.Context())
	err := r.service.generateAndSendPhoneToken(rc.Request.Context(), identity.GetPhone(), "verification")
	if err != nil {
		return errors.InternalServerError("an error occurred while generating and sending token")
	}
	return rc.WriteWithStatus(struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	}{"success", "sent successfully"}, http.StatusOK)
}

func (r resource) verifyEmailToken(rc *routing.Context) error {
	identity := CurrentAccount(rc.Request.Context())
	err, ok := r.service.verifyEmailToken(rc.Request.Context(), identity.GetID(), rc.Param("token"), strings.ToLower(rc.Param("purpose")))
	if !ok {
		if err == errors.InternalServerError("emailTokenExpired") {
			return errors.InternalServerError("email token expired")
		}
		return errors.InternalServerError("an error occurred while verifying the token")
	}
	return nil
}

func (r resource) verifyPhoneToken(rc *routing.Context) error {
	identity := CurrentAccount(rc.Request.Context())
	err, ok := r.service.verifyPhoneToken(rc.Request.Context(), identity.GetID(), rc.Param("token"), strings.ToLower(rc.Param("purpose")))
	if !ok {
		if err == errors.InternalServerError("phoneTokenExpired") {
			return errors.InternalServerError("phone token expired")
		}
		return errors.InternalServerError("an error occurred while verifying the token")
	}
	return nil
}

func (r resource) changePassword(rc *routing.Context) error {
	var input ChangePasswordRequest
	if err := rc.Read(&input); err != nil {
		r.logger.With(rc.Request.Context()).Errorf("problems occurred reading the payload: %v", err)
		return errors.BadRequest("")
	}

	identity := CurrentAccount(rc.Request.Context())
	_, ok := r.service.changePassword(rc.Request.Context(), identity.GetID(), identity.GetEmail(), input)
	if !ok {
		return errors.InternalServerError("an error occurred while verifying the token")
	}
	return rc.WriteWithStatus(struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	}{"success", "password changed successfully"}, http.StatusOK)
}

func (r resource) setupTOTP(rc *routing.Context) error {
	identity := CurrentAccount(rc.Request.Context())
	key, imageByte, err := r.service.setupTOTP(rc.Request.Context(), identity.GetEmail())
	if err != nil {
		return errors.InternalServerError("an error occurred while setting up the TOTP")
	}
	type data struct {
		SecretKey string `json:"secretKey"`
		ImageByte []byte `json:"imageByte"`
	}
	return rc.WriteWithStatus(struct {
		Status  string `json:"status"`
		Message string `json:"message"`
		Data    data   `json:"data"`
	}{"success", "TOTP was created successfully", data{SecretKey: key, ImageByte: imageByte}}, http.StatusOK)

}

func (r resource) validateTOTPFirstTime(rc *routing.Context) error {
	identity := CurrentAccount(rc.Request.Context())
	ok, err := r.service.validateTOTPFirstTime(rc.Request.Context(), identity.GetID(), identity.GetEmail(),
		rc.Param("passcode"), rc.Param("secret"))
	if !ok {
		if err == errors.InternalServerError("EmailAuthSet") {
			return errors.InternalServerError("Email has been set as the 2FA, unset to continue")
		}
		return errors.InternalServerError("an error occurred while validating totp for the first time")
	}
	return rc.WriteWithStatus(struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	}{"success", "TOTP was setup successfully"}, http.StatusOK)
}

func (r resource) validateTOTP(rc *routing.Context) error {
	identity := CurrentAccount(rc.Request.Context())
	if ok := r.service.validateTOTP(rc.Request.Context(), rc.Param("passcode"), identity.GetTOTPSecret()); !ok {
		return errors.InternalServerError("an error occurred while validating totp")
	}
	return rc.WriteWithStatus(struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	}{"success", "TOTP was setup successfully"}, http.StatusOK)
}

func (r resource) setup2FA(rc *routing.Context) error {
	identity := CurrentAccount(rc.Request.Context())
	err := r.service.set2FA(rc.Request.Context(), identity.GetID(), identity.GetEmail())
	if err != nil {
		if err == errors.InternalServerError("emailFaulty") {
			return errors.InternalServerError("email is not verified")
		}
		if err == errors.InternalServerError("GoogleAuthSet") {
			return errors.InternalServerError("Google auth has been set, unset to continue")
		}
		return errors.InternalServerError("an error occurred while verifying the token")
	}
	return rc.WriteWithStatus(struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	}{"success", "activated successfully"}, http.StatusOK)
}

func (r resource) checkAccountVerificationStatus(rc *routing.Context) error {
	identity := CurrentAccount(rc.Request.Context())
	err, mssg, _ := r.service.completedVerification(rc.Request.Context(), identity.GetEmail())
	if mssg != nil && err != nil {

		return rc.WriteWithStatus(struct {
			Status  string      `json:"status"`
			Message string      `json:"message"`
			Details interface{} `json:"details"`
		}{"failed", "not completed", mssg}, http.StatusOK)
	}
	return rc.WriteWithStatus(struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	}{"success", "completed"}, http.StatusOK)
}

//------------------------------------------------------TRANSACTION-----------------------------------------------------

func (r resource) paystackWebhookForTransaction(logger log.Logger) routing.Handler {
	return func(rc *routing.Context) error {
		logger := logger.With(rc.Request.Context(), "requestIpLoc", rc.Request.RemoteAddr)
		if rc.Request.Method != http.MethodPost {
			logger.Error("http method error")
			return errors2.New("invalid HTTP Method")
		}
		signature := rc.Request.Header.Get("X-Paystack-Signature")
		if len(signature) > 0 {
			payload, err := ioutil.ReadAll(rc.Request.Body)
			if err != nil || len(payload) == 0 {
				logger.Errorf("reading request body error: %s", err)
				return errors2.New("error passing payload")
			}
			if ok := r.service.webHookValid(string(payload), signature); !ok {
				logger.Error("webhook is not valid")
				return errors2.New("webhook is not valid")
			}
			var tmp map[string]interface{}
			_ = json.Unmarshal(payload, &tmp)

			if tmp["event"] == "charge.success" {
				var payloadHold ChargeSuccessPayload
				_ = json.Unmarshal(payload, &payloadHold)
				payloadAsString, _ := json.Marshal(payloadHold)

				//verify payment on paystack
				if ok := r.service.verifyOnPaystack(payloadHold.Data.Reference); !ok {
					logger.Error("payment verification failed")
					return errors2.New("payment failed verification")
				}

				//first get the account id from the transaction table
				transInfo, err := r.service.getTransactionByTransRef(rc.Request.Context(), payloadHold.Data.Reference)
				if err != nil {
					logger.Errorf("failed to retrieve transaction by ref: %s", err)
					return errors2.New("failed to retrieve transaction by ref")
				}

				//then we get the account information in search of the current balance
				acct, err := r.service.getAccountById(rc.Request.Context(), transInfo.AccountId)
				if err != nil {
					logger.Errorf("failed to retrieve account: %s", err)
					return errors2.New("failed to retrieve account")
				}

				//now we get the balance of the last transaction so as to help us increment or decrement as necessary
				currentBalance := acct.CurrentBalance + payloadHold.Data.Amount

				if payloadHold.Data.Status != "success" {
					logger.Error("trans not success")
					return errors2.New("transaction is not yet a success")
				}

				if transInfo.TransactionType == "" {
					if err := r.service.updateTrans(rc.Request.Context(), acct.Id, payloadHold.Data.Reference,
						payloadHold.Data.Status, "credit", payloadHold.Data.Currency, string(payloadAsString),
						payloadHold.Data.Amount, currentBalance); err != nil {
						logger.Errorf("failed to update the transaction and current balance: %s", err)
						return errors2.New("failed to update the transaction and current balance")
					}
					return rc.WriteWithStatus("", http.StatusOK)
				}
			}
		}
		logger.Errorf("transaction is not yet a success")
		return errors2.New("transaction is not yet a success")
	}
}

func (r resource) initiatedTransaction(rc *routing.Context) error {
	identity := CurrentAccount(rc.Request.Context())
	var input InitiateTransactionRequest
	if err := rc.Read(&input); err != nil {
		return errors.BadRequest("problems occurred reading the payload")
	}
	b, err := r.service.initiateTransaction(rc.Request.Context(), identity.GetID(), input)
	if err != nil {
		return rc.WriteWithStatus(struct {
			Status  string `json:"status"`
			Message string `json:"message"`
		}{"failed", "transaction initiation failed"}, http.StatusBadRequest)
	}

	type dataToReturn struct {
		Status  bool   `json:"status"`
		Message string `json:"message"`
		Data    struct {
			AuthorizationUrl string `json:"authorization_url,omitempty"`
			AccessCode       string `json:"access_code,omitempty"`
			Reference        string `json:"reference,omitempty"`
		} `json:"data"`
	}
	var dta *dataToReturn
	_ = json.Unmarshal(b, &dta)
	return rc.WriteWithStatus(dta, http.StatusOK)
}
