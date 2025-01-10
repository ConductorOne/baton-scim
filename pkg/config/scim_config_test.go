package scimconfig

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestServiceProviders(t *testing.T) {
	providers, err := getServiceProviders()

	require.NoError(t, err)
	require.Equal(t, len(providers), 4)

	// Test the first provider

	for _, provider := range providers {
		require.True(t, isSupportedServiceProvider(provider))
	}
}

func TestGetConfigBytes(t *testing.T) {
	yamlValue := `apiEndpoint: "https://api.getpostman.com/scim/v2/"
hasScimHeader: false
auth:
  authType: "apiKey"
user:
  id: "id"
  userName: "userName"
  firstName: "name.givenName"
  lastName: "name.familyName"
  primaryEmail: "userName"
  active: "active"
group:
  id: "id"
  displayName: "displayName"
  members:
    path: "members"
    id: "value"
    displayName: "display"
pagination:
  totalResults: "totalResults"
  itemsPerPage: "itemsPerPage"
  startIndex: "startIndex"
provisioning:
  addUserToGroup:
    schemas: "urn:ietf:params:scim:api:messages:2.0:PatchOp"
    op: "add"
    path: "members"
    valuePath: "value"
  removeUserFromGroup:
    schemas: "urn:ietf:params:scim:api:messages:2.0:PatchOp"
    op: "replace"
    path: "members"
    valuePath: "value"
`

	t.Run("File", func(t *testing.T) {
		tempFile, err := os.CreateTemp("", "baton-scim-test.yaml")
		require.NoError(t, err)

		_, err = tempFile.WriteString(yamlValue)
		require.NoError(t, err)

		defer func() {
			err := tempFile.Close()
			require.NoError(t, err)

			err = os.Remove(tempFile.Name())
			require.NoError(t, err)
		}()

		// Byte file
		value, err := getConfigBytes(tempFile.Name(), "", "")

		require.NoError(t, err)
		require.True(t, bytes.Equal(value, []byte(yamlValue)))
	})

	t.Run("Provider", func(t *testing.T) {
		// By provider
		providers, err := getServiceProviders()
		require.NoError(t, err)

		for _, provider := range providers {
			value, err := getConfigBytes("", provider, "")

			require.NoError(t, err)
			require.True(t, len(value) != 0)
		}
	})

	t.Run("RawValue", func(t *testing.T) {
		// By raw value
		value, err := getConfigBytes("", "", yamlValue)

		require.NoError(t, err)
		require.True(t, bytes.Equal(value, []byte(yamlValue)))
	})
}
