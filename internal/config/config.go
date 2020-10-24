package config

import (
	"github.com/go-ozzo/ozzo-validation/v4"
	"github.com/jokermario/monitri/pkg/log"
	"github.com/qiangxue/go-env"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
)

const (
	defaultServerPort         = "8080"
	defaultAccessExpirationHours = 1
	defaultRefreshExpirationHours = 72
)

// Config represents an application configuration.
type Config struct {
	// the server port. Defaults to 8080
	ServerPort string `yaml:"server_port" env:"SERVER_PORT"`
	// the data source name (DSN) for connecting to the database. required.
	DSN string `yaml:"dsn" env:"DSN,secret"`
	//AES Encryption Key
	EncKey string `yaml:"enc_key" env:"ENC_KEY,secret"`
	//Coinbase Key
	CKey string `yaml:"c_key" env:"C_KEY,secret"`
	//Coinbase Secret
	CSecret string `yaml:"c_secret" env:"C_SECRET, secret"`
	//paystack public key
	PPub string `yaml:"p_pub" env:"P_PUB,secret"`
	//paystack seceret key
	PSec string `yaml:"p_sec" env:"P_SEC, secret"`
	//paystack verify payment url
	PaystackURL string `yaml:"paystack_url" env:"PAYSTACK_URL"`
	// JWT access token signing key. required.
	AccessTokenSigningKey string `yaml:"jwt_access_token_signing_key" env:"JWT_ACCESS_TOKEN_SIGNING_KEY,secret"`
	// JWT refresh token signing key. required.
	RefreshTokenSigningKey string `yaml:"jwt_refresh_token_signing_key" env:"JWT_REFRESH_TOKEN_SIGNING_KEY,secret"`
	// JWT access token expiration in hours. Defaults to 5 hours
	AccessTokenExpiration int `yaml:"access_token_expiration" env:"JWT_EXPIRATION"`
	// JWT refresh token expiration in hours. Defaults to 72 hours (3 days)
	RefreshTokenExpiration int `yaml:"refresh_token_expiration" env:"JWT_EXPIRATION"`
	//the data source name for connecting to redis
	RedisDSN string `yaml:"redis_dsn" env:"REDIS_DSN"`
	//SMS Api Url
	SMSApiUrl string `yaml:"sms_api_url" env:"SMS_API_URL"`
	//SMS Username
	SMSUsername string `yaml:"sms_username" env:"SMS_USERNAME"`
	//SMS APIKEY
	SMSApiKey string `yaml:"sms_api_key" env:"SMS_API_KEY"`
	//Email host
	EmailUsername string `yaml:"email_username" env:"EMAIL_USERNAME"`
	//Email password
	EmailPassword string`yaml:"email_password" env:"EMAIL_PASSWORD"`
	//Email from
	EmailFrom string `yaml:"email_from" env:"EMAIL_FROM"`
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
		//ServerPort:    defaultServerPort,
		ServerPort: os.Getenv("PORT"),
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

	// load from environment variables prefixed with "MONITRI_"
	if err = env.New("MONITRI_", logger.Infof).Load(&c); err != nil {
		return nil, err
	}
	//for _, env := range os.Environ() {
	//	// env is
	//	envPair := strings.SplitN(env, "=", 2)
	//	key := envPair[0]
	//	value := envPair[1]
	//
	//	fmt.Printf("%s : %s\n", key, value)
	//}

	// validation
	if err = c.Validate(); err != nil {
		return nil, err
	}

	return &c, err
}
