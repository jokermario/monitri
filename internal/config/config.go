package config

import (
	"github.com/go-ozzo/ozzo-validation/v4"
	"github.com/qiangxue/go-env"
	"github.com/jokermario/monitri/pkg/log"
	"gopkg.in/yaml.v2"
	"io/ioutil"
)

const (
	defaultServerPort         = 8080
	defaultAccessExpirationHours = 1
	defaultRefreshExpirationHours = 72
)

// Config represents an application configuration.
type Config struct {
	// the server port. Defaults to 8080
	ServerPort int `yaml:"server_port" env:"SERVER_PORT"`
	// the data source name (DSN) for connecting to the database. required.
	DSN string `yaml:"dsn" env:"DSN,secret"`
	// JWT access token signing key. required.
	AccessTokenSigningKey string `yaml:"jwt_access_token_signing_key" env:"JWT_ACCESS_TOKEN_SIGNING_KEY,secret"`
	// JWT refresh token signing key. required.
	RefreshTokenSigningKey string `yaml:"jwt_refresh_token_signing_key" env:"JWT_REFRESH_TOKEN_SIGNING_KEY,secret"`
	// JWT access token expiration in hours. Defaults to 5 hours
	AccessTokenExpiration int `yaml:"access_token_expiration" env:"JWT_EXPIRATION"`
	// JWT refresh token expiration in hours. Defaults to 72 hours (3 days)
	RefreshTokenExpiration int `yaml:"refresh_token_expiration" env:"JWT_EXPIRATION"`
	//Sendgrid Api Key
	SendGridApiKey string `yaml:"sendgrid_api_key" env:"SENDGRID_API_KEY"`
	//the data source name for connecting to redis
	RedisDSN string `yaml:"redis_dsn" env:"REDIS_DSN"`
}

// Validate validates the application configuration.
func (c Config) Validate() error {
	return validation.ValidateStruct(&c,
		validation.Field(&c.DSN, validation.Required),
		validation.Field(&c.AccessTokenSigningKey, validation.Required),
		validation.Field(&c.RefreshTokenSigningKey, validation.Required),
	)
}

// Load returns an application configuration which is populated from the given configuration file and environment variables.
func Load(file string, logger log.Logger) (*Config, error) {
	// default config
	c := Config{
		ServerPort:    defaultServerPort,
		AccessTokenExpiration: defaultAccessExpirationHours,
		RefreshTokenExpiration: defaultRefreshExpirationHours,
	}

	// load from YAML config file
	bytes, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	if err = yaml.Unmarshal(bytes, &c); err != nil {
		return nil, err
	}

	// load from environment variables prefixed with "APP_"
	if err = env.New("APP_", logger.Infof).Load(&c); err != nil {
		return nil, err
	}

	// validation
	if err = c.Validate(); err != nil {
		return nil, err
	}

	return &c, err
}
