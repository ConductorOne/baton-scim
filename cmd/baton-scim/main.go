package main

import (
	"context"
	"fmt"
	"os"

	"github.com/conductorone/baton-scim/pkg/batonconfig"
	scimConfig "github.com/conductorone/baton-scim/pkg/config"
	"github.com/conductorone/baton-scim/pkg/connector"
	"github.com/conductorone/baton-scim/pkg/scim"

	"github.com/conductorone/baton-sdk/pkg/config"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/connectorrunner"
	"github.com/conductorone/baton-sdk/pkg/types"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

var version = "dev"

func main() {
	ctx := context.Background()

	_, cmd, err := config.DefineConfiguration(
		ctx,
		"baton-scim",
		getConnector,
		batonconfig.Config,
		connectorrunner.WithDefaultCapabilitiesConnectorBuilder(&connector.Connector{}),
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	cmd.Version = version

	err = cmd.Execute()
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func getConnector(ctx context.Context, cfg *batonconfig.Batonconfig) (types.ConnectorServer, error) {
	l := ctxzap.Extract(ctx)
	if err := batonconfig.ValidateConfig(cfg); err != nil {
		return nil, err
	}

	loadedScimConfig, err := scimConfig.LoadConfig(
		cfg.GetString(batonconfig.ScimConfigFileField.FieldName),
		cfg.GetString(batonconfig.ServiceProviderField.FieldName),
		cfg.GetString(batonconfig.ScimConfigValueField.FieldName),
	)
	if err != nil {
		l.Error("error loading config", zap.Error(err))
		return nil, err
	}

	connectorConfig := scim.ConnectorConfig{
		Username:         cfg.GetString(batonconfig.UsernameField.FieldName),
		Password:         cfg.GetString(batonconfig.PasswordField.FieldName),
		ApiKey:           cfg.GetString(batonconfig.ApiKeyField.FieldName),
		ScimClientID:     cfg.GetString(batonconfig.ScimClientIdField.FieldName),
		ScimClientSecret: cfg.GetString(batonconfig.ScimClientSecretField.FieldName),
		AccountID:        cfg.GetString(batonconfig.AccountIdField.FieldName),
		ServiceProvider:  cfg.GetString(batonconfig.ServiceProviderField.FieldName),
		ScimConfigFile:   cfg.GetString(batonconfig.ScimConfigFileField.FieldName),
	}

	cb, err := connector.New(ctx, loadedScimConfig, &connectorConfig)
	if err != nil {
		l.Error("error creating connector", zap.Error(err))
		return nil, err
	}

	c, err := connectorbuilder.NewConnector(ctx, cb)
	if err != nil {
		l.Error("error creating connector", zap.Error(err))
		return nil, err
	}

	return c, nil
}
