package accounts

import (
	routing "github.com/go-ozzo/ozzo-routing/v2"
	"github.com/gomodule/redigo/redis"
	"github.com/jokermario/monitri/internal/errors"
	"github.com/jokermario/monitri/pkg/log"
	"github.com/jokermario/monitri/pkg/pagination"
	"net/http"
)

func RegisterHandlers(r *routing.RouteGroup, service2 Service, JWTSigningKey string, logger log.Logger, redisConn redis.Conn) {
	res := resource{service2, logger, redisConn}
	authHandler := Handler(JWTSigningKey)


	r.Post("/login", res.login(logger))
	r.Post("/new/account", res.createAccount(logger))

	//write methods that do not require authentication here

	r.Use(authHandler)

	r.Get("/account/<id>", res.getById)
	r.Get("/account/<email>", res.getByEmail)
	r.Get("/user/all")
	r.Put("")
	r.Delete("/account/delete", res.deleteById)
}

type resource struct {
	service Service
	logger log.Logger
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

	account, err := r.service.UpdateProfile(rc.Request.Context(), rc.Param("id"), input)
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
		Success string `json:"success"`
	}{"deleted successfully"}, http.StatusOK)
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
		redisErr := r.service.storeAuthTokens(r.redisConn, req.Email, TokenDetails); if redisErr != nil {
			log.New().Infof("here")
			return redisErr
		}
		return c.Write(struct {
			TokenType string `json:"token_type"`
			AccessToken string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
		}{"Bearer", TokenDetails.AccessToken, TokenDetails.RefreshToken})
	}
}

func (r resource) createAccount(logger log.Logger) routing.Handler {
	return func(context *routing.Context) error {
		var input CreateAccountsRequest
		if err := context.Read(&input); err != nil {
			logger.With(context.Request.Context()).Errorf("problems occurred reading the payload: %v", err)
			return errors.BadRequest("")
		}

		TokenDetails, err := r.service.CreateAccount(context.Request.Context(), input)
		if err != nil {
			logger.With(context.Request.Context()).Errorf("problems occurred while creating an account: %v", err)
			return context.WriteWithStatus(errors.InternalServerError("email or phone already exist"), http.StatusBadRequest)
		}
		return context.WriteWithStatus(struct {
			TokenType string `json:"token_type"`
			AccessToken string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
		}{"Bearer", TokenDetails.AccessToken, TokenDetails.RefreshToken}, http.StatusOK)
	}
}