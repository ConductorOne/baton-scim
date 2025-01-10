package main

import (
	"fmt"

	"github.com/conductorone/baton-sdk/pkg/field"
	"github.com/spf13/viper"
)

var (
	ServiceProviderField = field.StringField(
		"service-provider",
		field.WithDescription("Name of the service provider to sync SCIM data from. E.g 'slack', 'zoom', 'miro', 'postman'."),
	)

	ScimConfigField = field.StringField(
		"scim-config",
		field.WithRequired(true),
		field.WithDescription("Path to your YAML SCIM configuration file."),
	)

	TokenField = field.StringField(
		"token",
		field.WithRequired(true),
		field.WithDescription("Token to authenticate with the SCIM API."),
	)

	ApiKeyField = field.StringField(
		"api-key",
		field.WithRequired(true),
		field.WithDescription("API key to authenticate with the SCIM API."),
	)

	UsernameField = field.StringField(
		"username",
		field.WithRequired(true),
		field.WithDescription("Username for basic auth to authenticate with the SCIM API."),
	)

	PasswordField = field.StringField(
		"password",
		field.WithRequired(true),
		field.WithDescription("Password for basic auth to authenticate with the SCIM API."),
	)

	ScimClientIdField = field.StringField(
		"scim-client-id",
		field.WithRequired(true),
		field.WithDescription("Client ID used to obtain access token for the SCIM API."),
	)

	ScimClientSecretField = field.StringField(
		"scim-client-secret",
		field.WithRequired(true),
		field.WithDescription("Client Secret used to obtain access token for the SCIM API. ($BATON_SCIM_CLIENT_SECRET)"),
	)

	ScimConfigFileField = field.StringField(
		"scim-config-file",
		field.WithDescription("Path to your YAML SCIM configuration file."),
	)

	ScimConfigValueField = field.StringField(
		"scim-config-value",
		field.WithDescription("raw value of YAML SCIM configuration file."),
	)

	AccountIdField = field.StringField(
		"account-id",
		field.WithRequired(true),
		field.WithDescription("Account ID used to obtain access token for the SCIM API."),
	)

	// ConfigurationFields defines the external configuration required for the
	// connector to run. Note: these fields can be marked as optional or
	// required.
	ConfigurationFields = []field.SchemaField{
		ServiceProviderField,
		ScimConfigField,
		TokenField,
		ApiKeyField,
		UsernameField,
		PasswordField,
		ScimClientIdField,
		ScimClientSecretField,
		ScimConfigFileField,
		AccountIdField,
		ScimConfigValueField,
	}

	// FieldRelationships defines relationships between the fields listed in
	// ConfigurationFields that can be automatically validated. For example, a
	// username and password can be required together, or an access token can be
	// marked as mutually exclusive from the username password pair.
	FieldRelationships = []field.SchemaFieldRelationship{}
)

// ValidateConfig is run after the configuration is loaded, and should return an
// error if it isn't valid. Implementing this function is optional, it only
// needs to perform extra validations that cannot be encoded with configuration
// parameters.
func ValidateConfig(v *viper.Viper) error {
	if (v.GetString(ApiKeyField.FieldName) == "" && v.GetString(TokenField.FieldName) == "") &&
		(v.GetString(UsernameField.FieldName) == "" || v.GetString(PasswordField.FieldName) == "") &&
		(v.GetString(ScimClientIdField.FieldName) == "" || v.GetString(ScimClientSecretField.FieldName) == "") {
		return fmt.Errorf("either token, api-key or username and password, or scim-client-id and scim-client-secret must be provided")
	}

	if v.GetString(ScimConfigFileField.FieldName) == "" &&
		v.GetString(ServiceProviderField.FieldName) == "" &&
		v.GetString(ScimConfigValueField.FieldName) == "" {
		return fmt.Errorf("either scim-config-file, service-provider or scim-config-value must be provided")
	}

	return nil
}
