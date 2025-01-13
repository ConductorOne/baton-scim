package scim

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/PaesslerAG/jsonpath"
	scimConfig "github.com/conductorone/baton-scim/pkg/config"
	"github.com/conductorone/baton-sdk/pkg/uhttp"
)

const (
	users             = "Users"
	groups            = "Groups"
	defaultPageNumber = 1
	defaultPageSize   = 100
	zoom              = "zoom"

	// JsonPath common expressions.
	allResources    = "$.Resources[*]"
	currentResource = "$"

	// Auth types.
	apiKey = "apiKey"
	basic  = "basic"
)

type Client struct {
	httpClient       *uhttp.BaseHttpClient
	config           *scimConfig.SCIMConfig
	serviceProvider  string
	apiKey           string
	username         string
	password         string
	scimClientID     string
	scimClientSecret string
	accountID        string
}

type ConnectorConfig struct {
	ScimConfigFile   string
	ServiceProvider  string
	Username         string
	Password         string
	ApiKey           string
	ScimClientID     string
	ScimClientSecret string
	AccountID        string
}

type PaginationVars struct {
	StartIndex    int `json:"page"`
	ItemsReturned int `json:"itemsReturned"`
	Count         int `json:"count,omitempty"`
}

// FilterOptions TODO: extend filter options
type FilterOptions struct {
	// Filter group by name.
	Name string
	// Filter user by username.
	UserName string
}

type PatchOp struct {
	Schemas    []string    `json:"schemas"`
	Operations []Operation `json:"Operations"`
}

type Operation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}

type AuthVars struct {
	ServiceProvider string
	AuthUrl         string
	AccountId       string
	ClientID        string
	ClientSecret    string
}

type PutOp struct {
	Schemas []string     `json:"schemas"`
	Roles   []AssignRole `json:"Operations"`
}

type AssignRole struct {
	Display string `json:"display,omitempty"`
	Value   string `json:"value,omitempty"`
}

type RateLimitError struct {
	RetryAfter time.Duration
}

func (r *RateLimitError) Error() string {
	return fmt.Sprintf("rate limited, retry after: %s", r.RetryAfter.String())
}

func NewClient(httpClient *http.Client, config scimConfig.SCIMConfig, connectorConfig *ConnectorConfig) (*Client, error) {
	return &Client{
		httpClient:       uhttp.NewBaseHttpClient(httpClient),
		config:           &config,
		serviceProvider:  connectorConfig.ServiceProvider,
		apiKey:           connectorConfig.ApiKey,
		username:         connectorConfig.Username,
		password:         connectorConfig.Password,
		scimClientID:     connectorConfig.ScimClientID,
		scimClientSecret: connectorConfig.ScimClientSecret,
		accountID:        connectorConfig.AccountID,
	}, nil
}

func (c *Client) ListUsers(ctx context.Context, pagination PaginationVars) ([]User, Token, error) {
	usersUrl, err := url.JoinPath(c.config.ApiEndpoint, users)
	if err != nil {
		return nil, Token{}, err
	}

	pageNumber := defaultPageNumber
	if pagination.StartIndex != 0 {
		pageNumber = pagination.StartIndex
	}

	totalReturned := 0
	if pagination.ItemsReturned != 0 {
		totalReturned = pagination.ItemsReturned
	}

	pageSize := defaultPageSize
	if pagination.Count != 0 {
		pageSize = pagination.Count
	}

	data, err := c.doRequest(ctx, http.MethodGet, usersUrl, PaginationVars{StartIndex: pageNumber, Count: pageSize}, nil, FilterOptions{})
	if err != nil {
		return nil, Token{}, fmt.Errorf("error fetching SCIM users: %w", err)
	}

	var jsonData interface{}
	err = json.Unmarshal(data, &jsonData)
	if err != nil {
		return nil, Token{}, fmt.Errorf("error unmarshaling user data: %w", err)
	}

	resources, err := jsonpath.Get(allResources, jsonData)
	if err != nil {
		return nil, Token{}, fmt.Errorf("error extracting user resources: %w", err)
	}

	resourceArray, ok := resources.([]interface{})
	if !ok {
		return nil, Token{}, fmt.Errorf("invalid resource format")
	}

	var result []User
	for _, resource := range resourceArray {
		user, err := MapUser(ctx, resource, &c.config.User)
		if err != nil {
			return nil, Token{}, fmt.Errorf("error mapping user data: %w", err)
		}
		result = append(result, user)
	}

	paginationData, err := MapPagination(data, &c.config.Pagination)
	if err != nil {
		return nil, Token{}, fmt.Errorf("error mapping pagination: %w", err)
	}

	totalReturned += paginationData.ItemsPerPage

	if totalReturned >= paginationData.TotalResults {
		return result, Token{}, nil
	}

	var token Token
	token.NextPage = strconv.Itoa(totalReturned + 1)
	token.ItemsReturned = strconv.Itoa(totalReturned)

	return result, token, nil
}

func (c *Client) GetUser(ctx context.Context, userID string) (User, error) {
	userUrl, err := url.JoinPath(c.config.ApiEndpoint, users, userID)
	if err != nil {
		return User{}, err
	}

	data, err := c.doRequest(ctx, http.MethodGet, userUrl, PaginationVars{}, nil, FilterOptions{})
	if err != nil {
		return User{}, fmt.Errorf("error fetching SCIM user details: %w", err)
	}

	var jsonData interface{}
	err = json.Unmarshal(data, &jsonData)
	if err != nil {
		return User{}, fmt.Errorf("error unmarshaling user data: %w", err)
	}

	userResource, err := jsonpath.Get(currentResource, jsonData)
	if err != nil {
		return User{}, fmt.Errorf("error extracting user resource: %w", err)
	}

	var mappedUser User
	mappedUser, err = MapUser(ctx, userResource, &c.config.User)
	if err != nil {
		return User{}, fmt.Errorf("error mapping user data: %w", err)
	}

	return mappedUser, nil
}

func (c *Client) ListGroups(ctx context.Context, pagination PaginationVars, filters FilterOptions) ([]Group, Token, error) {
	groupsUrl, err := url.JoinPath(c.config.ApiEndpoint, groups)
	if err != nil {
		return nil, Token{}, err
	}

	pageNumber := defaultPageNumber
	if pagination.StartIndex != 0 {
		pageNumber = pagination.StartIndex
	}

	totalReturned := 0
	if pagination.ItemsReturned != 0 {
		totalReturned = pagination.ItemsReturned
	}

	pageSize := defaultPageSize
	if pagination.Count != 0 {
		pageSize = pagination.Count
	}

	data, err := c.doRequest(ctx, http.MethodGet, groupsUrl, PaginationVars{StartIndex: pageNumber, Count: pageSize}, nil, filters)
	if err != nil {
		return nil, Token{}, fmt.Errorf("error fetching SCIM groups: %w", err)
	}

	var jsonData interface{}
	err = json.Unmarshal(data, &jsonData)
	if err != nil {
		return nil, Token{}, fmt.Errorf("error unmarshaling groups data: %w", err)
	}

	resources, err := jsonpath.Get(allResources, jsonData)
	if err != nil {
		return nil, Token{}, fmt.Errorf("error extracting group resources: %w", err)
	}

	resourceArray, ok := resources.([]interface{})
	if !ok {
		return nil, Token{}, fmt.Errorf("invalid resource format")
	}

	var result []Group
	for _, resource := range resourceArray {
		group, err := MapGroup(resource, &c.config.Group)
		if err != nil {
			return nil, Token{}, fmt.Errorf("error mapping group data: %w", err)
		}
		result = append(result, group)
	}

	paginationData, err := MapPagination(data, &c.config.Pagination)
	if err != nil {
		return nil, Token{}, fmt.Errorf("error mapping pagination: %w", err)
	}

	totalReturned += paginationData.ItemsPerPage

	if totalReturned >= paginationData.TotalResults {
		return result, Token{}, nil
	}

	var token Token
	token.NextPage = strconv.Itoa(totalReturned + 1)
	token.ItemsReturned = strconv.Itoa(totalReturned)

	return result, token, nil
}

func (c *Client) GetGroup(ctx context.Context, groupID string) (Group, error) {
	groupUrl, err := url.JoinPath(c.config.ApiEndpoint, groups, groupID)
	if err != nil {
		return Group{}, err
	}

	data, err := c.doRequest(ctx, http.MethodGet, groupUrl, PaginationVars{}, nil, FilterOptions{})
	if err != nil {
		return Group{}, fmt.Errorf("error fetching SCIM group details: %w", err)
	}

	var jsonData interface{}
	err = json.Unmarshal(data, &jsonData)
	if err != nil {
		return Group{}, fmt.Errorf("error unmarshaling group data: %w", err)
	}

	groupResource, err := jsonpath.Get(currentResource, jsonData)
	if err != nil {
		return Group{}, fmt.Errorf("error extracting group resource: %w", err)
	}

	var mappedGroup Group
	mappedGroup, err = MapGroup(groupResource, &c.config.Group)
	if err != nil {
		return Group{}, fmt.Errorf("error mapping group data: %w", err)
	}

	return mappedGroup, nil
}

// AddUserToGroup patches a group by adding a user to it.
func (c *Client) AddUserToGroup(ctx context.Context, groupID string, userID string) error {
	operation := c.config.Provisioning.AddUserToGroup
	requestBody := PatchOp{
		Schemas: []string{operation.Schemas},
		Operations: []Operation{
			{
				Op:   strings.ToLower(operation.Op),
				Path: operation.Path,
				Value: []map[string]string{
					{operation.ValuePath: userID},
				},
			},
		},
	}

	urlRequest, err := url.JoinPath(c.config.ApiEndpoint, groups, groupID)
	if err != nil {
		return fmt.Errorf("error parsing URL: %w", err)
	}

	_, err = c.doRequest(ctx, http.MethodPatch, urlRequest, PaginationVars{}, requestBody, FilterOptions{})
	if err != nil {
		return fmt.Errorf("error adding user to group: %w", err)
	}

	return nil
}

// RemoveUserFromGroup patches a group by removing a user from it.
func (c *Client) RemoveUserFromGroup(ctx context.Context, groupID string, userID string) error {
	operation := c.config.Provisioning.RemoveUserFromGroup
	// need to fetch group to get existing members
	group, err := c.GetGroup(ctx, groupID)
	if err != nil {
		return fmt.Errorf("error fetching group: %w", err)
	}

	var result []map[string]string
	for _, member := range group.Members {
		if member.ID != userID {
			result = append(result, map[string]string{operation.ValuePath: member.ID})
		}
	}

	requestBody := PatchOp{
		Schemas: []string{operation.Schemas},
		Operations: []Operation{
			{
				Op:    strings.ToLower(operation.Op),
				Path:  operation.Path,
				Value: result,
			},
		},
	}

	urlRequest, err := url.JoinPath(c.config.ApiEndpoint, groups, groupID)
	if err != nil {
		return fmt.Errorf("error parsing URL: %w", err)
	}

	_, err = c.doRequest(ctx, http.MethodPatch, urlRequest, PaginationVars{}, requestBody, FilterOptions{})

	if err != nil {
		return fmt.Errorf("error removing user from group: %w", err)
	}

	return nil
}

// AddUserRole patches a user by adding a role to it.
// If the service provider is Zoom, the role is added using a PUT request.
func (c *Client) AddUserRole(ctx context.Context, roleName string, userID string) error {
	operation := c.config.Provisioning.AddUserRole
	method := http.MethodPatch
	var requestBody interface{}
	// zoom has a different schema for adding/removing roles
	if c.serviceProvider == zoom {
		requestBody = PutOp{
			Schemas: []string{operation.Schemas},
			Roles:   []AssignRole{{Display: roleName, Value: roleName}},
		}
		method = http.MethodPut
	} else {
		requestBody = PatchOp{
			Schemas: []string{operation.Schemas},
			Operations: []Operation{
				{
					Op:   strings.ToLower(operation.Op),
					Path: operation.Path,
					Value: []map[string]string{
						{operation.ValuePath: roleName},
					},
				},
			},
		}
	}

	urlRequest, err := url.JoinPath(c.config.ApiEndpoint, users, userID)
	if err != nil {
		return fmt.Errorf("error parsing URL: %w", err)
	}

	_, err = c.doRequest(ctx, method, urlRequest, PaginationVars{}, requestBody, FilterOptions{})
	if err != nil {
		return fmt.Errorf("error granting user role: %w", err)
	}

	return nil
}

// RevokeUserRole patches a user by removing a role from it.
func (c *Client) RevokeUserRole(ctx context.Context, roleName string, userID string) error {
	operation := c.config.Provisioning.RemoveUserRole
	method := http.MethodPatch
	var requestBody interface{}
	if c.serviceProvider == zoom {
		method = http.MethodPut
		requestBody = PutOp{
			Schemas: []string{operation.Schemas},
			Roles:   []AssignRole{},
		}
	} else {
		requestBody = PatchOp{
			Schemas: []string{operation.Schemas},
			Operations: []Operation{
				{
					Op:    strings.ToLower(operation.Op),
					Path:  operation.Path,
					Value: []map[string]string{},
				},
			},
		}
	}

	urlRequest, err := url.JoinPath(c.config.ApiEndpoint, users, userID)
	if err != nil {
		return fmt.Errorf("error parsing URL: %w", err)
	}

	_, err = c.doRequest(ctx, method, urlRequest, PaginationVars{}, requestBody, FilterOptions{})
	if err != nil {
		return fmt.Errorf("error revoking user role: %w", err)
	}

	return nil
}

func (c *Client) doRequest(ctx context.Context, method string, reqUrl string, paginationVars PaginationVars, payload interface{}, filters FilterOptions) ([]byte, error) {
	u, err := url.Parse(reqUrl)
	if err != nil {
		return nil, err
	}

	var authHeader uhttp.RequestOption
	var acceptHeader uhttp.RequestOption

	if c.config.HasScimHeader {
		acceptHeader = uhttp.WithHeader("Accept", "application/scim+json")
	} else {
		acceptHeader = uhttp.WithAcceptJSONHeader()
	}

	switch c.config.Auth.AuthType {
	case apiKey:
		if c.apiKey == "" {
			return nil, fmt.Errorf("missing api key")
		}
		apiKeyHeader := c.apiKey
		if c.config.Auth.ApiKeyPrefix != "" {
			apiKeyHeader = fmt.Sprintf("%s %s", c.config.Auth.ApiKeyPrefix, c.apiKey)
		}
		authHeader = uhttp.WithHeader("Authorization", apiKeyHeader)
	case basic:
		if c.username == "" || c.password == "" {
			return nil, fmt.Errorf("missing username or password")
		}
	default:
		return nil, fmt.Errorf("unsupported auth type: %s", c.config.Auth.AuthType)
	}

	req, err := c.httpClient.NewRequest(
		ctx,
		method,
		u,
		uhttp.WithJSONBody(payload),
		uhttp.WithAcceptJSONHeader(),
		acceptHeader,
		authHeader,
	)
	if err != nil {
		return nil, err
	}

	if c.config.Auth.AuthType == basic {
		req.SetBasicAuth(c.username, c.password)
	}

	q := url.Values{}
	if paginationVars.Count != 0 {
		q.Add("count", fmt.Sprintf("%d", paginationVars.Count))
		q.Add("startIndex", fmt.Sprintf("%d", paginationVars.StartIndex))
	}

	if filters.Name != "" {
		q.Add("filter", fmt.Sprintf("displayName eq \"%s\"", filters.Name))
	}

	if filters.UserName != "" {
		q.Add("filter", fmt.Sprintf("userName eq \"%s\"", filters.UserName))
	}

	if len(q) > 0 {
		req.URL.RawQuery = q.Encode()
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		retryAfter := resp.Header.Get("Retry-After")
		retryAfterSec, err := strconv.Atoi(retryAfter)
		if err != nil {
			return nil, fmt.Errorf("error parsing retry after header: %w", err)
		}
		return nil, &RateLimitError{RetryAfter: time.Second * time.Duration(retryAfterSec)}
	}

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
		if req.Method == http.MethodPut || req.Method == http.MethodPatch {
			return nil, nil // no body expected/needed for these methods
		}
	}

	return body, nil
}

type AuthBody struct {
	GrantType string `json:"grant_type"`
	AccountID string `json:"account_id"`
}

// RequestAccessToken creates bearer token.
func RequestAccessToken(ctx context.Context, vars AuthVars, tokenPath string) (string, error) {
	httpClient, err := (&uhttp.NoAuth{}).GetClient(ctx)
	if err != nil {
		return "", err
	}

	client := uhttp.NewBaseHttpClient(httpClient)
	u, err := url.Parse(vars.AuthUrl)
	if err != nil {
		return "", err
	}

	var payload AuthBody
	// Zoom requires account_id for token request
	if vars.AccountId != "" && vars.ServiceProvider == zoom {
		payload = AuthBody{
			GrantType: "account_credentials",
			AccountID: vars.AccountId,
		}
	}

	req, err := client.NewRequest(ctx, http.MethodPost, u, uhttp.WithJSONBody(payload), uhttp.WithAcceptJSONHeader(), uhttp.WithContentTypeJSONHeader())
	if err != nil {
		return "", fmt.Errorf("error creating request: %w", err)
	}

	req.SetBasicAuth(vars.ClientID, vars.ClientSecret)

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error requesting auth token: %w", err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading auth response: %w", err)
	}

	var jsonData interface{}
	err = json.Unmarshal(body, &jsonData)
	if err != nil {
		return "", fmt.Errorf("error unmarshaling auth data: %w", err)
	}

	token, err := jsonpath.Get(tokenPath, jsonData)
	if err != nil {
		return "", fmt.Errorf("error extracting auth token: %w", err)
	}

	tokenStr, ok := token.(string)
	if !ok {
		return "", fmt.Errorf("unexpected token type")
	}

	return tokenStr, nil
}
