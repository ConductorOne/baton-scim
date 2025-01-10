![Baton Logo](./baton-logo.png)

#

`baton-scim` [![Go Reference](https://pkg.go.dev/badge/github.com/conductorone/baton-scim.svg)](https://pkg.go.dev/github.com/conductorone/baton-scim) ![main ci](https://github.com/conductorone/baton-scim/actions/workflows/main.yaml/badge.svg)

`baton-scim` is a generic connector for various SCIM service providers built using
the [Baton SDK](https://github.com/conductorone/baton-sdk). It communicates with the SCIM API to sync data about users,
groups and roles.
Currently supported service providers:

- miro
- postman
- slack
- zoom

In case service provider you want to sync your data from is missing in the current implementation, you can pass your own
yaml configuration file. Examples of these configuration files can be found in `service_providers` folder in the
repository.
Check out [Baton](https://github.com/conductorone/baton) to learn more about the project in general.

# Getting Started

## Prerequisites

1. Configured SSO and enabled SCIM for your service provider.
2. Choose the service provider:

- In case of syncing with already configured service providers, a flag `--service-provider` should be passed with the
  name of the provider. E.g --service-provider=slack
- In case of a new service provider, a path to your yaml config file should be provided via `--scim-config-file` flag.
  Config file should contain information about the service provider and also mappings for user, group and role resources
  in SCIM. Resources are extracted using [JSONPath](https://goessner.net/articles/JsonPath) expressions which help map
  various different responses to the predefined types for the resources used in the connector. That's why some fields in
  the config are required in order for connector to run properly. More info about JSONPath can be
  found [here](https://pkg.go.dev/github.com/PaesslerAG/jsonpath).

Config file example:

```
  apiEndpoint: "https://api.zoom.us/scim2/" // Required. SCIM API endpoint for your service provider.
  authType: "oauth2" // Required. Type of authentication used. Can be "oauth2", "apiKey" or "basic"
  hasScimHeader: true // Required. In case your service provider requires a special Accept header for SCIM.
  shouldObtainToken: true // In case the auth token should be obtained programatically.
  authUrl: "https://zoom.us/oauth/token" // Auth url for obtaining the token, required if shouldObtainToken is true.
  tokenPath: "access_token" // TokenPath represents the name of field in the auth response where token is, required if shouldObtainToken is true.
  user: // mappings for user resource using JSONPath expressions.
    id: "id" // Required.
    userName: "userName" // Required.
    firstName: "name.givenName" // Required.
    lastName: "name.familyName" // Required.
    primaryEmail: "emails[?(@.primary==true)].value" // JSONpath for primary email in response.
    firstEmail: "emails[0].value" // JSONpath for first email in response.
    active: "active" // Required
    hasGroupsOnUser: true // In case your API doesn't have Members in Group object, Group can usually be found in User object.
    userGroup: // Group mappings for Group in User object.
      path: groups // Required.
      name: display // Required.
    roles: // Role mappings on User object.
      path: "roles" // Required.
      name: "roles.value" // Required.
      display: "roles.display"
  group: // Group mappings.
    id: "id" // Required.
    displayName: "displayName" // Required.
  pagination: // Pagination mappings.
    totalResults: "totalResults" // Required.
    itemsPerPage: "itemsPerPage" // Required.
    startIndex: "startIndex" // Required.
  provisioning: // Mappings for Group membership and User role provisioning.
    addUserToGroup: // All fields are required.
      schemas: "urn:ietf:params:scim:api:messages:2.0:PatchOp"
      op: "add"
      path: "members"
      valuePath: "value"
    removeUserFromGroup: // All fields are required.
      schemas: "urn:ietf:params:scim:api:messages:2.0:PatchOp"
      op: "replace"
      path: "members"
      valuePath: "value"
    addUserRole: // All fields are required.
      schemas: "urn:ietf:params:scim:api:messages:2.0:ListResponse"
      op: "add"
      path: "roles"
      valuePath: "value"
    removeUserRole: // All fields are required.
      schemas: "urn:ietf:params:scim:api:messages:2.0:ListResponse"
      op: "remove"
      path: "roles"
      valuePath: "value"
```

3. Auth info:

- in case auth token or api key can be obtained in the service provider interface pass it via `--token` flag for "
  oauth2" auth type, or as `--api-key` flag for "apiKey" auth type.
- in case of "basic" auth type, provide username and password via `--username`and `--password` flags.
- in case token should be obtained via oauth2 flow in the app, pass Client ID and Client Secret via `--scim-client-id`
  and `--scim-client-secret` flags.

## brew

```
brew install conductorone/baton/baton conductorone/baton/baton-scim

BATON_TOKEN=oauth2Token BATON_SERVICE_PROVIDER=slack baton-scim
baton resources
```

or

```
brew install conductorone/baton/baton conductorone/baton/baton-scim

BATON_API_KEY=apiKEy BATON_SCIM_CONFIG=path/to/your/config/serviceProvider.yaml baton-scim
baton resources
```

## docker

```
docker run --rm -v $(pwd):/out -e BATON_TOKEN=oauth2Token BATON_SERVICE_PROVIDER=slack baton-scim ghcr.io/conductorone/baton-scim:latest -f "/out/sync.c1z"
docker run --rm -v $(pwd):/out ghcr.io/conductorone/baton:latest -f "/out/sync.c1z" resources
```

## source

```
go install github.com/conductorone/baton/cmd/baton@main
go install github.com/conductorone/baton-scim/cmd/baton-scim@main

BATON_TOKEN=oauth2Token BATON_SERVICE_PROVIDER=slack baton-scim
baton resources
```

# Data Model

`baton-scim` will pull down information about the following resources:

- Users
- Groups
- Roles

# Contributing, Support and Issues

We started Baton because we were tired of taking screenshots and manually building spreadsheets. We welcome
contributions, and ideas, no matter how small -- our goal is to make identity and permissions sprawl less painful for
everyone. If you have questions, problems, or ideas: Please open a Github Issue!

See [CONTRIBUTING.md](https://github.com/ConductorOne/baton/blob/main/CONTRIBUTING.md) for more details.

# `baton-scim` Command Line Usage

```
baton-scim

Usage:
  baton-scim [flags]
  baton-scim [command]

Available Commands:
  completion         Generate the autocompletion script for the specified shell
  help               Help about any command

Flags:
      --account-id string           Account ID used to obtain access token for the SCIM API. ($BATON_ACCOUNT_ID)
      --api-key string              API key to authenticate with the SCIM API. ($BATON_API_KEY)
      --client-id string            The client ID used to authenticate with ConductorOne ($BATON_CLIENT_ID)
      --client-secret string        The client secret used to authenticate with ConductorOne ($BATON_CLIENT_SECRET)
  -f, --file string                 The path to the c1z file to sync with ($BATON_FILE) (default "sync.c1z")
  -h, --help                        help for baton-scim
      --log-format string           The output format for logs: json, console ($BATON_LOG_FORMAT) (default "json")
      --log-level string            The log level: debug, info, warn, error ($BATON_LOG_LEVEL) (default "info")
      --password string             Password for basic auth to authenticate with the SCIM API. ($BATON_PASSWORD)
  -p, --provisioning                This must be set in order for provisioning actions to be enabled. ($BATON_PROVISIONING)
      --scim-client-id string       Client ID used to obtain access token for the SCIM API. ($BATON_SCIM_CLIENT_ID)
      --scim-client-secret string   Client Secret used to obtain access token for the SCIM API. ($BATON_SCIM_CLIENT_SECRET)
      --scim-config string          Path to your YAML SCIM configuration file. ($BATON_SCIM_CONFIG)
      --service-provider string     Name of the service provider to sync SCIM data from. E.g 'slack', 'zoom'. ($BATON_SERVICE_PROVIDER)
      --token string                Token to authenticate with the SCIM API. ($BATON_TOKEN)
      --username string             Username for basic auth to authenticate with the SCIM API. ($BATON_USERNAME)
  -v, --version                     version for baton-scim

Use "baton-scim [command] --help" for more information about a command.
```
