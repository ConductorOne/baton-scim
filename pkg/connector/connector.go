package connector

import (
	"context"
	"fmt"

	scimConfig "github.com/conductorone/baton-scim/pkg/config"
	"github.com/conductorone/baton-scim/pkg/scim"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/uhttp"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
)

type Connector struct {
	client     *scim.Client
	scimConfig *scimConfig.SCIMConfig
}

// ResourceSyncers returns a ResourceSyncer for each resource type that should be synced from the upstream service.
func (d *Connector) ResourceSyncers(ctx context.Context) []connectorbuilder.ResourceSyncer {
	return []connectorbuilder.ResourceSyncer{
		newUserBuilder(d.client, &d.scimConfig.User),
		newGroupBuilder(d.client),
		newRoleBuilder(d.client),
	}
}

// Metadata returns metadata about the connector.
func (d *Connector) Metadata(ctx context.Context) (*v2.ConnectorMetadata, error) {
	return &v2.ConnectorMetadata{
		DisplayName: "Baton SCIM connector",
		Description: "Generic SCIM connector that syncs users and groups from SCIM API based on provided config.",
	}, nil
}

// Validate is called to ensure that the connector is properly configured. It should exercise any API credentials
// to be sure that they are valid.
func (d *Connector) Validate(ctx context.Context) (annotations.Annotations, error) {
	_, _, err := d.client.ListUsers(ctx, scim.PaginationVars{Count: 1})
	if err != nil {
		return nil, fmt.Errorf("error validating connector: %w", err)
	}
	return nil, nil
}

// New returns a new instance of the connector.
func New(ctx context.Context, scimConfig *scimConfig.SCIMConfig, connectorConfig *scim.ConnectorConfig) (*Connector, error) {
	httpClient, err := uhttp.NewClient(ctx, uhttp.WithLogger(true, ctxzap.Extract(ctx)))
	if err != nil {
		return nil, err
	}

	authToken := connectorConfig.Token
	// If the token is not provided and the connector is configured to obtain it, request a new token.
	if scimConfig.Auth.ShouldObtainToken {
		authToken, err = scim.RequestAccessToken(ctx, scim.AuthVars{
			AuthUrl:         scimConfig.Auth.AuthUrl,
			AccountId:       connectorConfig.AccountID,
			ClientID:        connectorConfig.ScimClientID,
			ClientSecret:    connectorConfig.ScimClientSecret,
			ServiceProvider: connectorConfig.ServiceProvider,
		}, scimConfig.Auth.TokenPath)
		if err != nil {
			return nil, fmt.Errorf("scim-connector: failed to get token: %w", err)
		}
	}

	connectorConfig.Token = authToken

	client, err := scim.NewClient(httpClient, *scimConfig, connectorConfig)
	if err != nil {
		return nil, fmt.Errorf("error creating client: %w", err)
	}

	return &Connector{
		client:     client,
		scimConfig: scimConfig,
	}, nil
}
