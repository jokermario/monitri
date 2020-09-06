package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"github.com/go-ozzo/ozzo-dbx"
	"github.com/go-ozzo/ozzo-routing/v2"
	"github.com/go-ozzo/ozzo-routing/v2/content"
	"github.com/go-ozzo/ozzo-routing/v2/cors"
	"github.com/gomodule/redigo/redis"
	"github.com/jokermario/monitri/internal/accounts"
	"github.com/jokermario/monitri/internal/config"
	"github.com/jokermario/monitri/internal/email"
	"github.com/jokermario/monitri/internal/errors"
	"github.com/jokermario/monitri/internal/healthcheck"
	"github.com/jokermario/monitri/pkg/accesslog"
	"github.com/jokermario/monitri/pkg/dbcontext"
	"github.com/jokermario/monitri/pkg/log"
	_ "github.com/lib/pq"
	"net/http"
	"os"
	"time"
)

// Version indicates the current version of the application.
var Version = "1.0.0"

var flagConfig = flag.String("config", "./config/local.yml", "path to the config file")

func main() {
	flag.Parse()
	// create root logger tagged with server version
	logger := log.New().With(nil, "version", Version)

	// load application configurations
	cfg, err := config.Load(*flagConfig, logger)
	if err != nil {
		logger.Errorf("failed to load application configuration: %s", err)
		os.Exit(-1)
	}

	//connect to redis
	redisConn := redisConnPool(cfg.RedisDSN).Get()
	log.New().Infof(cfg.RedisDSN)
	defer func() {
		if err := redisConn.Close(); err != nil {
			logger.Error(err)
		}
	}()

	// connect to the database
	db, err := dbx.MustOpen("postgres", cfg.DSN)
	if err != nil {
		logger.Error(err)
		os.Exit(-1)
	}
	db.QueryLogFunc = logDBQuery(logger)
	db.ExecLogFunc = logDBExec(logger)
	defer func() {
		if err := db.Close(); err != nil {
			logger.Error(err)
		}
	}()

	// build HTTP server
	address := fmt.Sprintf(":%v", cfg.ServerPort)
	hs := &http.Server{
		Addr:    address,
		Handler: buildHandler(logger, dbcontext.New(db), cfg, redisConn),
	}

	// start the HTTP server with graceful shutdown
	go routing.GracefulShutdown(hs, 10*time.Second, logger.Infof)
	logger.Infof("server %v is running at %v", Version, address)
	if err := hs.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error(err)
		os.Exit(-1)
	}
}

// buildHandler sets up the HTTP routing and builds an HTTP handler.
func buildHandler(logger log.Logger, db *dbcontext.DB, cfg *config.Config, redisConn redis.Conn) http.Handler {
	router := routing.New()

	router.Use(
		accesslog.Handler(logger),
		errors.Handler(logger),
		content.TypeNegotiator(content.JSON),
		cors.Handler(cors.AllowAll),
	)

	healthcheck.RegisterHandlers(router, Version)

	rg := router.Group("/v1")

	//authHandler := auth.Handler(cfg.JWTSigningKey)
	//
	//album.RegisterHandlers(rg.Group(""),
	//	album.NewService(album.NewRepository(db, logger), logger),
	//	authHandler, logger,
	//)
	accounts.RegisterHandlers(rg.Group(""),
		accounts.NewService(
			accounts.NewRepository(
				db,
				logger),
			logger,
			email.NewService(logger, cfg.SendGridApiKey),
			cfg.AccessTokenSigningKey,
			cfg.RefreshTokenSigningKey,
			cfg.AccessTokenExpiration,
			cfg.RefreshTokenExpiration),
		cfg.AccessTokenSigningKey, logger, redisConn)

	//auth.RegisterHandlers(rg.Group(""),
	//	auth.NewService(cfg.JWTSigningKey, cfg.JWTExpiration, logger, accounts.NewRepository(db, logger), email.NewService(logger, cfg.SendGridApiKey)),
	//	logger,
	//)

	return router
}

// logDBQuery returns a logging function that can be used to log SQL queries.
func logDBQuery(logger log.Logger) dbx.QueryLogFunc {
	return func(ctx context.Context, t time.Duration, sql string, rows *sql.Rows, err error) {
		if err == nil {
			logger.With(ctx, "duration", t.Milliseconds(), "sql", sql).Info("DB query successful")
		} else {
			logger.With(ctx, "sql", sql).Errorf("DB query error: %v", err)
		}
	}
}

// logDBExec returns a logging function that can be used to log SQL executions.
func logDBExec(logger log.Logger) dbx.ExecLogFunc {
	return func(ctx context.Context, t time.Duration, sql string, result sql.Result, err error) {
		if err == nil {
			logger.With(ctx, "duration", t.Milliseconds(), "sql", sql).Info("DB execution successful")
		} else {
			logger.With(ctx, "sql", sql).Errorf("DB execution error: %v", err)
		}
	}
}

//redisConnPool returns a redis conn instance to be used
func redisConnPool(redisDSN string) *redis.Pool{
	return &redis.Pool{
		//Maximum number of idle connections int he pool
		MaxIdle: 80,
		//Maximum number of connections
		MaxActive: 12000,
		//Dial is an application supplied function for creating and configuring a connection
		Dial: func() (redis.Conn, error) {
			conn, err := redis.Dial("tcp", redisDSN)
			if err != nil {
				panic(err.Error())
			}
			return conn, err
		},
	}
}
