package main

import (
	"context"
	"fmt"
	"os"

	scimConfig "github.com/conductorone/baton-scim/pkg/config"
	"github.com/conductorone/baton-scim/pkg/connector"
	"github.com/conductorone/baton-scim/pkg/scim"
	"github.com/spf13/viper"

	"github.com/conductorone/baton-sdk/pkg/config"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/field"
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
		field.Configuration{
			Fields: ConfigurationFields,
		},
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

func getConnector(ctx context.Context, v *viper.Viper) (types.ConnectorServer, error) {
	l := ctxzap.Extract(ctx)
	if err := ValidateConfig(v); err != nil {
		return nil, err
	}

	loadedScimConfig, err := scimConfig.LoadConfig(
		v.GetString(ScimConfigFileField.FieldName),
		v.GetString(ServiceProviderField.FieldName),
		v.GetString(ScimConfigValueField.FieldName),
	)
	if err != nil {
		l.Error("error loading config", zap.Error(err))
		return nil, err
	}

	connectorConfig := scim.ConnectorConfig{
		Username:         v.GetString(UsernameField.FieldName),
		Password:         v.GetString(PasswordField.FieldName),
		ApiKey:           v.GetString(ApiKeyField.FieldName),
		ScimClientID:     v.GetString(ScimClientIdField.FieldName),
		ScimClientSecret: v.GetString(ScimClientSecretField.FieldName),
		AccountID:        v.GetString(AccountIdField.FieldName),
		ServiceProvider:  v.GetString(ServiceProviderField.FieldName),
		ScimConfigFile:   v.GetString(ScimConfigFileField.FieldName),
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
