package main

import (
	"context"
	"fmt"

	"github.com/conductorone/baton-sdk/pkg/cli"
	"github.com/spf13/cobra"
)

// config defines the external configuration required for the connector to run.
type config struct {
	cli.BaseConfig   `mapstructure:",squash"` // Puts the base config options in the same place as the connector options
	ScimConfigFile   string                   `mapstructure:"scim-config"`
	Token            string                   `mapstructure:"token"`
	ServiceProvider  string                   `mapstructure:"service-provider"`
	Username         string                   `mapstructure:"username"`
	Password         string                   `mapstructure:"password"`
	ApiKey           string                   `mapstructure:"api-key"`
	ScimClientID     string                   `mapstructure:"scim-client-id"`
	ScimClientSecret string                   `mapstructure:"scim-client-secret"`
	AccountID        string                   `mapstructure:"account-id"`
}

// validateConfig is run after the configuration is loaded, and should return an error if it isn't valid.
func validateConfig(ctx context.Context, cfg *config) error {
	if (cfg.ApiKey == "" && cfg.Token == "") &&
		(cfg.Username == "" || cfg.Password == "") &&
		(cfg.ScimClientID == "" || cfg.ScimClientSecret == "") {
		return fmt.Errorf("either token, api-key or username and password, or scim-client-id and scim-client-secret must be provided")
	}

	if cfg.ScimConfigFile == "" && cfg.ServiceProvider == "" {
		return fmt.Errorf("either scim-config or service-provider must be provided")
	}

	return nil
}

// cmdFlags sets the cmdFlags required for the connector.
func cmdFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().String("service-provider", "", "Name of the service provider to sync SCIM data from. E.g 'slack', 'zoom'. ($BATON_SERVICE_PROVIDER)")
	cmd.PersistentFlags().String("scim-config", "", "Path to your YAML SCIM configuration file. ($BATON_SCIM_CONFIG)")
	cmd.PersistentFlags().String("token", "", "Token to authenticate with the SCIM API. ($BATON_TOKEN)")
	cmd.PersistentFlags().String("api-key", "", "API key to authenticate with the SCIM API. ($BATON_API_KEY)")
	cmd.PersistentFlags().String("username", "", "Username for basic auth to authenticate with the SCIM API. ($BATON_USERNAME)")
	cmd.PersistentFlags().String("password", "", "Password for basic auth to authenticate with the SCIM API. ($BATON_PASSWORD)")
	cmd.PersistentFlags().String("scim-client-id", "", "Client ID used to obtain access token for the SCIM API. ($BATON_SCIM_CLIENT_ID)")
	cmd.PersistentFlags().String("scim-client-secret", "", "Client Secret used to obtain access token for the SCIM API. ($BATON_SCIM_CLIENT_SECRET)")
	cmd.PersistentFlags().String("account-id", "", "Account ID used to obtain access token for the SCIM API. ($BATON_ACCOUNT_ID)")
}
