package batonconfig

import (
	"fmt"

	"github.com/conductorone/baton-sdk/pkg/field"
)

var ServiceProviderField = field.StringField(
	"service-provider",
	field.WithDescription("Name of the service provider to sync SCIM data from. E.g 'slack', 'zoom', 'miro', 'postman'."),
)

var ScimConfigField = field.StringField(
	"scim-config",
	field.WithDescription("Path to your YAML SCIM configuration file."),
)

var ApiKeyField = field.StringField(
	"api-key",
	field.WithDescription("API key to authenticate with the SCIM API."),
)

var UsernameField = field.StringField(
	"username",
	field.WithDescription("Username for basic auth to authenticate with the SCIM API."),
)

var PasswordField = field.StringField(
	"password",
	field.WithDescription("Password for basic auth to authenticate with the SCIM API."),
)

var ScimClientIdField = field.StringField(
	"scim-client-id",
	field.WithDescription("Client ID used to obtain access token for the SCIM API."),
)

var ScimClientSecretField = field.StringField(
	"scim-client-secret",
	field.WithDescription("Client Secret used to obtain access token for the SCIM API. ($BATON_SCIM_CLIENT_SECRET)"),
)

var ScimConfigFileField = field.StringField(
	"scim-config-file",
	field.WithDescription("Path to your YAML SCIM configuration file."),
)

var ScimConfigValueField = field.StringField(
	"scim-config-value",
	field.WithDescription("raw value of YAML SCIM configuration file."),
)

var AccountIdField = field.StringField(
	"account-id",
	field.WithDescription("Account ID used to obtain access token for the SCIM API."),
)

// FieldRelationships defines relationships between the fields listed in
// Config that can be automatically validated.
var FieldRelationships = []field.SchemaFieldRelationship{}

//go:generate go run ./gen

// Config defines the external configuration required for the connector to run.
var Config = field.NewConfiguration([]field.SchemaField{
	ServiceProviderField,
	ScimConfigField,
	ApiKeyField,
	UsernameField,
	PasswordField,
	ScimClientIdField,
	ScimClientSecretField,
	ScimConfigFileField,
	AccountIdField,
	ScimConfigValueField,
})

// ValidateConfig is run after the configuration is loaded, and should return an
// error if it isn't valid.
func ValidateConfig(cfg *Batonconfig) error {
	if (cfg.GetString(ApiKeyField.FieldName) == "") &&
		(cfg.GetString(UsernameField.FieldName) == "" || cfg.GetString(PasswordField.FieldName) == "") &&
		(cfg.GetString(ScimClientIdField.FieldName) == "" || cfg.GetString(ScimClientSecretField.FieldName) == "") {
		return fmt.Errorf("either api-key, username and password, or scim-client-id and scim-client-secret must be provided")
	}

	if cfg.GetString(ScimConfigFileField.FieldName) == "" &&
		cfg.GetString(ServiceProviderField.FieldName) == "" &&
		cfg.GetString(ScimConfigValueField.FieldName) == "" {
		return fmt.Errorf("either scim-config-file, service-provider or scim-config-value must be provided")
	}

	return nil
}
