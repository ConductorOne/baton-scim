package main

import (
	"context"
	"fmt"
	"os"

	"github.com/conductorone/baton-sdk/pkg/cli"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/types"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"

	scimConfig "github.com/conductorone/baton-scim/pkg/config"
	"github.com/conductorone/baton-scim/pkg/connector"
	scim "github.com/conductorone/baton-scim/pkg/scim"
)

var version = "dev"

func main() {
	ctx := context.Background()

	cfg := &config{}
	cmd, err := cli.NewCmd(ctx, "baton-scim", cfg, validateConfig, getConnector)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	cmd.Version = version
	cmdFlags(cmd)

	err = cmd.Execute()
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func getConnector(ctx context.Context, cfg *config) (types.ConnectorServer, error) {
	l := ctxzap.Extract(ctx)

	scimConfig, err := scimConfig.LoadConfig(cfg.ScimConfigFile, cfg.ServiceProvider)
	if err != nil {
		l.Error("error loading config", zap.Error(err))
		return nil, err
	}

	config := scim.ConnectorConfig{
		Token:            cfg.Token,
		Username:         cfg.Username,
		Password:         cfg.Password,
		ApiKey:           cfg.ApiKey,
		ScimClientID:     cfg.ScimClientID,
		ScimClientSecret: cfg.ScimClientSecret,
		AccountID:        cfg.AccountID,
		ServiceProvider:  cfg.ServiceProvider,
		ScimConfigFile:   cfg.ScimConfigFile,
	}

	cb, err := connector.New(ctx, scimConfig, &config)
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
