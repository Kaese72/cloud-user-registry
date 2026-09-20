package config

import (
	"context"
	"os"
	"strings"

	"github.com/pkg/errors"

	"github.com/Kaese72/cloud-user-registry/internal/logging"
	"github.com/spf13/viper"
)

type DatabaseConfig struct {
	Host     string `json:"host" mapstructure:"host"`
	Port     int    `json:"port" mapstructure:"port"`
	User     string `json:"user" mapstructure:"user"`
	Password string `json:"password" mapstructure:"password"`
	Database string `json:"database" mapstructure:"database"`
}

func (conf DatabaseConfig) Validate() error {
	if conf.Host == "" {
		return errors.New("must supply database host")
	}
	return nil
}

type AuthConfig struct {
	RSAPrivateKeyPath      string `json:"rsa-private-key-path" mapstructure:"rsa-private-key-path"`
	RefreshSecret          string `json:"refresh-secret" mapstructure:"refresh-secret"`
	UseTokenExpiryMinutes  int    `json:"use-token-expiry-minutes" mapstructure:"use-token-expiry-minutes"`
	RefreshTokenExpiryDays int    `json:"refresh-token-expiry-days" mapstructure:"refresh-token-expiry-days"`
	// ServiceTokens is a comma-separated list of static bearer tokens other
	// cloud services (appliance-registry) use to call the internal endpoints.
	// A list so a token can be rotated without a synchronized cutover.
	ServiceTokens string `json:"service-tokens" mapstructure:"service-tokens"`
}

func (conf AuthConfig) Validate() error {
	if conf.RSAPrivateKeyPath == "" {
		return errors.New("must supply auth rsa-private-key-path")
	}
	if conf.RefreshSecret == "" {
		return errors.New("must supply auth refresh-secret")
	}
	if conf.ServiceTokens == "" {
		return errors.New("must supply auth service-tokens")
	}
	return nil
}

type SMTPConfig struct {
	Host     string `json:"host" mapstructure:"host"`
	Port     int    `json:"port" mapstructure:"port"`
	Username string `json:"username" mapstructure:"username"`
	Password string `json:"password" mapstructure:"password"`
	From     string `json:"from" mapstructure:"from"`
}

func (conf SMTPConfig) Validate() error {
	if conf.Host == "" {
		return errors.New("must supply smtp host")
	}
	if conf.From == "" {
		return errors.New("must supply smtp from address")
	}
	return nil
}

// PasswordResetConfig configures the "forgot password" email flow.
type PasswordResetConfig struct {
	// TokenExpiryMinutes is how long a reset link stays valid after being
	// emailed.
	TokenExpiryMinutes int `json:"token-expiry-minutes" mapstructure:"token-expiry-minutes"`
	// URLBase is the cloud-ui page the reset link points to; the reset
	// token is appended as a "?token=" query parameter.
	URLBase string `json:"url-base" mapstructure:"url-base"`
}

func (conf PasswordResetConfig) Validate() error {
	if conf.URLBase == "" {
		return errors.New("must supply password-reset url-base")
	}
	return nil
}

type Config struct {
	Database      DatabaseConfig      `json:"database" mapstructure:"database"`
	Auth          AuthConfig          `json:"auth" mapstructure:"auth"`
	SMTP          SMTPConfig          `json:"smtp" mapstructure:"smtp"`
	PasswordReset PasswordResetConfig `json:"password-reset" mapstructure:"password-reset"`
	Port          int                 `json:"port" mapstructure:"port"`
	// InternalPort serves the endpoints meant only for other cloud services
	// (see internalwebapp). It is deliberately a separate listener from Port:
	// the public ingress routes to Port and never to this one, so these
	// endpoints are not reachable from the internet at all, and the service
	// token is defence in depth rather than the only barrier.
	InternalPort int `json:"internal-port" mapstructure:"internal-port"`
}

func (conf Config) Validate() error {
	if err := conf.Database.Validate(); err != nil {
		return err
	}
	if err := conf.Auth.Validate(); err != nil {
		return err
	}
	if err := conf.SMTP.Validate(); err != nil {
		return err
	}
	if err := conf.PasswordReset.Validate(); err != nil {
		return err
	}
	return nil
}

var Loaded Config

func init() {
	// We have elected to not use AutomaticEnv() because of https://github.com/spf13/viper/issues/584
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))

	viper.BindEnv("database.host")
	viper.BindEnv("database.port")
	viper.BindEnv("database.user")
	viper.BindEnv("database.password")
	viper.BindEnv("database.database")
	viper.SetDefault("database.port", 3306)
	viper.SetDefault("database.database", "clouduserregistry")

	viper.BindEnv("auth.rsa-private-key-path")
	viper.BindEnv("auth.refresh-secret")
	viper.BindEnv("auth.use-token-expiry-minutes")
	viper.SetDefault("auth.use-token-expiry-minutes", 10)
	viper.BindEnv("auth.refresh-token-expiry-days")
	viper.SetDefault("auth.refresh-token-expiry-days", 7)
	viper.BindEnv("auth.service-tokens")

	viper.BindEnv("smtp.host")
	viper.BindEnv("smtp.port")
	viper.SetDefault("smtp.port", 587)
	viper.BindEnv("smtp.username")
	viper.BindEnv("smtp.password")
	viper.BindEnv("smtp.from")

	viper.BindEnv("password-reset.token-expiry-minutes")
	viper.SetDefault("password-reset.token-expiry-minutes", 30)
	viper.BindEnv("password-reset.url-base")

	viper.BindEnv("logging.stdout")
	viper.SetDefault("logging.stdout", true)
	viper.BindEnv("logging.http.url")

	viper.BindEnv("port")
	viper.SetDefault("port", 8080)
	viper.BindEnv("internal-port")
	viper.SetDefault("internal-port", 8081)

	err := viper.Unmarshal(&Loaded)
	if err != nil {
		logging.Error(err.Error(), context.TODO())
		os.Exit(1)
	}
}
