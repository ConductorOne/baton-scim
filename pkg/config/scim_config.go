package scimconfig

import (
	"embed"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/go-playground/validator/v10"
	"gopkg.in/yaml.v2"
)

//go:embed service_providers
var serviceProviders embed.FS

type SCIMConfig struct {
	// The URL of the SCIM API endpoint
	ApiEndpoint string `yaml:"apiEndpoint" validate:"required,url"`
	// Some providers require a specific Accept header when working with SCIM
	HasScimHeader bool                `yaml:"hasScimHeader" validate:"boolean"`
	Auth          AuthOptions         `yaml:"auth" validate:"required"`
	User          UserMapping         `yaml:"user" validate:"required"`
	Group         GroupMapping        `yaml:"group" validate:"required"`
	Pagination    PaginationMapping   `yaml:"pagination" validate:"required"`
	Provisioning  ProvisioningMapping `yaml:"provisioning" validate:"omitempty"`
}

// Mapping for the authentication configuration.
type AuthOptions struct {
	// Type of authentication to use
	AuthType string `yaml:"authType" validate:"required,oneof=basic oauth2 apiKey"`
	// ApiKey prefix, if using an API key
	ApiKeyPrefix string `yaml:"apiKeyPrefix" validate:"omitempty"`
	// If there is no token provided beforehand and this is set to 'true' the connector will obtain one
	ShouldObtainToken bool `yaml:"shouldObtainToken" validate:"boolean"`
	// Auth URL called to obtain the token
	AuthUrl string `yaml:"authUrl" validate:"required_if=ShouldObtainToken true"`
	// Name of the token field in the response. (jsonpath)
	TokenPath string `yaml:"tokenPath" validate:"required_if=ShouldObtainToken true"`
}

// Mapping for the pagination configuration.
type PaginationMapping struct {
	TotalResults string `yaml:"totalResults" validate:"required"`
	ItemsPerPage string `yaml:"itemsPerPage" validate:"required"`
	StartIndex   string `yaml:"startIndex" validate:"required"`
}

// Mapping for the group configuration.
type GroupMapping struct {
	// Name of the ID field in the group object. (jsonpath)
	ID string `yaml:"id" validate:"required"`
	// Name of the DisplayName field in the group object. (jsonpath)
	DisplayName string `yaml:"displayName" validate:"required"`
	// Member mapping options, if present
	Members MemberMapping `yaml:"members" validate:"omitempty"`
}

// Mapping for the members array in the group object.
type MemberMapping struct {
	// Name of the members field in the group object. (jsonpath)
	Path string `yaml:"path" validate:"required"`
	// Name of the ID field in the member object. (jsonpath)
	ID string `yaml:"id" validate:"required"`
	// Name of the DisplayName field in the member object, if present. (jsonpath)
	DisplayName string `yaml:"displayName" validate:"omitempty"`
}

// Mapping for the user configuration.
type UserMapping struct {
	// Name of the ID field in the user object. (jsonpath)
	ID string `yaml:"id" validate:"required"`
	// Name of the UserName field in the user object. (jsonpath)
	Username string `yaml:"userName"`
	// Name of the FirstName field in the user object. (jsonpath)
	FirstName string `yaml:"firstName" validate:"required"`
	// Name of the LastName field in the user object. (jsonpath)
	LastName string `yaml:"lastName" validate:"required"`
	// JsonPath for primary email in case SCIM API has a primary field for the email
	PrimaryEmail string `yaml:"primaryEmail" validate:"required"`
	// JsonPath for the first email in case SCIM API has an array of emails without a primary field
	FirstEmail string `yaml:"firstEmail"`
	// Name of the Active field in the user object. (jsonpath)
	Active string `yaml:"active" validate:"required"`
	// Role mapping options, if present
	Roles RoleMapping `yaml:"roles" validate:"omitempty"`
	// If the groups are on the user object, not in a separate endpoint
	HasGroupsOnUser bool `yaml:"hasGroupsOnUser" validate:"boolean,omitempty"`
	// Group mapping on the user object, if present
	UserGroup UserGroupMapping `yaml:"userGroup" validate:"required_if=HasGroupsOnUser true"`
}

// Mapping for the user group configuration.
type UserGroupMapping struct {
	// Name of the Groups field in the user object. (jsonpath)
	Path string `yaml:"path" validate:"required_if=HasGroupsOnUser true"`
	// Name of the Group field in the group object. (jsonpath)
	Name string `yaml:"name" validate:"required_if=HasGroupsOnUser true"`
	// Name of the ID field in the group object, if present. (jsonpath)
	ID string `yaml:"id" validate:"omitempty"`
}

// Mapping for the role configuration.
type RoleMapping struct {
	// Name of the Roles field in the user object. (jsonpath)
	Path string `yaml:"path" validate:"required"`
	// Name of the Name field in the role object. (jsonpath)
	Name string `yaml:"name" validate:"required_with=Path"`
	// Name of the DisplayName field in the role object, if present. (jsonpath)
	Display string `yaml:"display" validate:"omitempty"`
}

// Mapping for the provisioning configuration.
type ProvisioningMapping struct {
	AddUserRole         PatchOperation `yaml:"addUserRole" validate:"omitempty"`
	RemoveUserRole      PatchOperation `yaml:"removeUserRole" validate:"omitempty"`
	AddUserToGroup      PatchOperation `yaml:"addUserToGroup" validate:"omitempty"`
	RemoveUserFromGroup PatchOperation `yaml:"removeUserFromGroup" validate:"omitempty"`
}

// Group membership and User role provisioning are usually done with PATCH operations.
type PatchOperation struct {
	// Schemas array, always required 1 value
	Schemas string `yaml:"schemas" validate:"required"`
	// Name of the operation, e.g. 'add', 'remove'
	Op string `yaml:"op" validate:"required"`
	// Operation path, e.g. 'roles', 'members'
	Path string `yaml:"path" validate:"required"`
	// Name of the value field in the operation object. (jsonpath)
	ValuePath string `yaml:"valuePath" validate:"required"`
}

func LoadConfig(filename string, serviceProvider string) (*SCIMConfig, error) {
	var configFile string
	switch {
	case filename != "" && serviceProvider != "":
		return nil, fmt.Errorf("only one of scim-config or service-provider must be provided")
	case filename == "" && serviceProvider == "":
		return nil, fmt.Errorf("either scim-config or service-provider must be provided")
	case filename != "":
		configFile = filename
	case serviceProvider != "":
		if !isSupportedServiceProvider(serviceProvider) {
			return nil, fmt.Errorf("unsupported service provider: %s", serviceProvider)
		}
		configFile = fmt.Sprintf("service_providers/%s.yaml", serviceProvider)
	default:
		return nil, fmt.Errorf("unexpected error")
	}

	file, err := serviceProviders.Open(configFile)
	if err != nil {
		return nil, fmt.Errorf("error reading config file: %w", err)
	}
	defer file.Close()

	buf, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	var config SCIMConfig
	err = yaml.Unmarshal(buf, &config)
	if err != nil {
		return nil, fmt.Errorf("error parsing config file: %w", err)
	}

	validate := validator.New(validator.WithRequiredStructEnabled())
	err = validate.Struct(config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}

func isSupportedServiceProvider(serviceProvider string) bool {
	supportedServiceProviders, err := getServiceProviders()
	if err != nil {
		return false
	}

	for _, supported := range supportedServiceProviders {
		if serviceProvider == supported {
			return true
		}
	}
	return false
}

func getServiceProviders() ([]string, error) {
	files, err := serviceProviders.ReadDir("service_providers")
	if err != nil {
		return nil, fmt.Errorf("error reading config directory: %w", err)
	}

	var serviceProviderNames []string
	for _, file := range files {
		if !file.IsDir() && filepath.Ext(file.Name()) == ".yaml" {
			// Remove the extension to get just the service provider name
			serviceProviderName := strings.TrimSuffix(file.Name(), filepath.Ext(file.Name()))
			serviceProviderNames = append(serviceProviderNames, serviceProviderName)
		}
	}

	return serviceProviderNames, nil
}
