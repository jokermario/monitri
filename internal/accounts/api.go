package accounts

import "C"
import (
	routing "github.com/go-ozzo/ozzo-routing/v2"
	"github.com/gomodule/redigo/redis"
	"github.com/jokermario/monitri/internal/errors"
	"github.com/jokermario/monitri/pkg/log"
	"github.com/jokermario/monitri/pkg/pagination"
	"net/http"
	"time"
)

func RegisterHandlers(r *routing.RouteGroup, service2 Service, AccessTokenSigningKey,
	RefreshTokenSigningKey string, logger log.Logger, redisConn redis.Conn) {
	res := resource{service2, logger, redisConn}

	authHandler := Handler(AccessTokenSigningKey, RefreshTokenSigningKey, service2, redisConn)

	r.Post("/generate/token", res.login(logger))
	r.Post("/new/account", res.createAccount(logger))

	r.Use(authHandler)

	r.Get("/account/<id>", res.getById)
	r.Get("/account/<email>", res.getByEmail)
	r.Get("/user/all")
	r.Put("")
	r.Delete("/account/delete", res.deleteById)
	r.Post("/account/logout", res.logout)
	r.Post("/refresh/token", res.refreshToken)
	r.Post("/account/email/token", res.sendEmailVeriToken)
	r.Post("/account/phone/token", res.sendPhoneVeriToken)
	r.Post("/account/verify/email/<token>", res.verifyEmailVeriToken)
	r.Post("/account/verify/phone/<token>", res.verifyPhoneVeriToken)
	r.Post("/account/change/password", res.changePassword)
}

type resource struct {
	service   Service
	logger    log.Logger
	redisConn redis.Conn
}

func (r resource) getById(rc *routing.Context) error {
	account, err := r.service.GetById(rc.Request.Context(), rc.Param("id"))
	if err != nil {
		return err
	}
	return rc.WriteWithStatus(account, http.StatusOK)
}

func (r resource) getByEmail(rc *routing.Context) error {
	account, err := r.service.GetAccountByEmail(rc.Request.Context(), rc.Param("email"))
	if err != nil {
		return err
	}
	return rc.WriteWithStatus(account, http.StatusOK)
}

func (r resource) updateProfile(rc *routing.Context) error {
	var input UpdateAccountRequest
	if err := rc.Read(&input); err != nil {
		r.logger.With(rc.Request.Context()).Error(err)
		return errors.BadRequest("")
	}

	identity := CurrentAccount(rc.Request.Context())
	account, err := r.service.UpdateProfile(rc.Request.Context(), identity.GetID(), input)
	if err != nil {
		r.logger.With(rc.Request.Context()).Error(err)
		return errors.BadRequest("")
	}

	return rc.WriteWithStatus(account, http.StatusOK)
}

func (r resource) getAccounts(rc *routing.Context) error {
	ctx := rc.Request.Context()
	count, err := r.service.Count(ctx)
	if err != nil {
		r.logger.With(ctx).Error(err)
		return err
	}
	pages := pagination.NewFromRequest(rc.Request, count)
	account, err := r.service.GetAccounts(ctx, pages.Offset(), pages.Limit())
	if err != nil {
		r.logger.With(ctx).Error(err)
		return err
	}
	pages.Items = account
	return rc.WriteWithStatus(pages, http.StatusOK)
}

func (r resource) deleteById(rc *routing.Context) error {
	identity := CurrentAccount(rc.Request.Context())
	if err := r.service.DeleteById(rc.Request.Context(), identity.GetID()); err != nil {
		r.logger.With(rc.Request.Context()).Error(err)
		return err
	}
	return rc.WriteWithStatus(struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	}{"success", "deleted successfully"}, http.StatusOK)
}

// login returns a handler that handles accounts login request.
func (r resource) login(logger log.Logger) routing.Handler {
	return func(c *routing.Context) error {
		var req LoginRequest

		if err := c.Read(&req); err != nil {
			logger.With(c.Request.Context()).Errorf("invalid request: %v", err)
			return errors.BadRequest("")
		}
		TokenDetails, err := r.service.Login(c.Request.Context(), req)
		if err != nil {
			return err
		}
		redisErr := r.service.storeAuthKeys(r.redisConn, req.Email, TokenDetails)
		if redisErr != nil {
			return redisErr
		}

		r.service.sendLoginNotifEmail(c.Request.Context(), req.Email, time.Now().Format(time.RFC3339), c.Request.RemoteAddr, c.Request.UserAgent())

		return c.Write(struct {
			TokenType    string `json:"token_type"`
			AccessToken  string `json:"access_token"`
			ExpiryTime   int64  `json:"expires"`
			RefreshToken string `json:"refresh_token"`
		}{"Bearer", TokenDetails.AccessToken, TokenDetails.AtExpires,
			TokenDetails.RefreshToken})
	}
}

func (r resource) createAccount(logger log.Logger) routing.Handler {
	return func(context *routing.Context) error {
		var input CreateAccountsRequest
		if err := context.Read(&input); err != nil {
			logger.With(context.Request.Context()).Errorf("problems occurred reading the payload: %v", err)
			return errors.BadRequest("")
		}

		err := r.service.CreateAccount(context.Request.Context(), input)
		if err != nil {
			logger.With(context.Request.Context()).Errorf("problems occurred while creating an account: %v", err)
			return context.WriteWithStatus(errors.InternalServerError("email or phone already exist"),
				http.StatusBadRequest)
		}
		return context.WriteWithStatus(struct {
			Status  string `json:"status"`
			Message string `json:"message"`
		}{"success", "Account created successfully"}, http.StatusOK)
	}
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

	tokenDetails, err := r.service.generateTokens(userIdentity)
	if err != nil {
		return errors.InternalServerError("a problem occurred while trying to generate a new access token")
	}
	TokenDetails, refErr := r.service.refreshToken(userIdentity, r.redisConn, identity.GetEmail(), tokenDetails)
	if refErr != nil {
		return errors.InternalServerError("an error occurred while storing the refresh token")
	}

	//deletes the refresh token from redis
	_ = r.service.logOut(rc.Request.Context(), r.redisConn, identity.GetRefreshID())
	return rc.Write(struct {
		TokenType    string `json:"token_type"`
		AccessToken  string `json:"access_token"`
		ExpiryTime   int64  `json:"expires"`
		RefreshToken string `json:"refresh_token"`
	}{"Bearer", TokenDetails.AccessToken, TokenDetails.AtExpires,
		TokenDetails.RefreshToken})
}

func (r resource) sendEmailVeriToken(rc *routing.Context) error {
	identity := CurrentAccount(rc.Request.Context())
	err := r.service.generateAndSendEmailVerificationToken(rc.Request.Context(), identity.GetEmail())
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
	err := r.service.generateAndSendPhoneVerificationToken(rc.Request.Context(), identity.GetPhone())
	if err != nil {
		return errors.InternalServerError("an error occurred while generating and sending token")
	}
	return rc.WriteWithStatus(struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	}{"success", "sent successfully"}, http.StatusOK)
}

func (r resource) verifyEmailVeriToken(rc *routing.Context) error {
	identity := CurrentAccount(rc.Request.Context())
	_, ok := r.service.verifyEmailVerificationToken(rc.Request.Context(), identity.GetID(), rc.Param("token"))
	if !ok {
		return errors.InternalServerError("an error occurred while verifying the token")
	}
	return nil
}

func (r resource) verifyPhoneVeriToken(rc *routing.Context) error {
	identity := CurrentAccount(rc.Request.Context())
	_, ok := r.service.verifyPhoneVerificationToken(rc.Request.Context(), identity.GetID(), rc.Param("token"))
	if !ok {
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
	_, ok := r.service.ChangePassword(rc.Request.Context(), identity.GetID(), identity.GetEmail(), input)
	if !ok {
		return errors.InternalServerError("an error occurred while verifying the token")
	}
	return rc.WriteWithStatus(struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	}{"success", "password changed successfully"}, http.StatusOK)
}
