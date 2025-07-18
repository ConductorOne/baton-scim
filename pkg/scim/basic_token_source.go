package scim

/*
	BASIC TOKEN SOURCE
	  Since we may find some SCIM APIs that implement grant type: 'client credentials'
	  with the grant_type indicated as a query param and BASIC Auth to request the new Token,
	  this basic_token_source was implemented to maintain the valid token updated.
	  The idea of this implementation is to just request the Token using a basic HTTP Client. That's it.

	FAQs:
	- WHEN TO USE IT?
		When your SCIM API has client credentials as grant type, no refresh token and Basic Auth to request that Bearer token.
		Also, in this type of implementations, no specific scopes are indicated when requesting the Token.

	- IS THIS REALLY NECESSARY AND USEFUL?
		Well, if there are two SCIM APIs like this, there may be three.

	- ISN'T THIS VERY SPECIFIC TO BE ON THE BASE SCIM CONNECTOR?
		It looks like, and it may receive updates in the close future, like reading the 'grant_type' from a config property.
		Atm this is useful for a couple of APIs, but may be upgraded when the time comes. (hopefully soon).
*/

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/conductorone/baton-sdk/pkg/uhttp"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

type BasicTokenSource struct {
	Ctx          context.Context
	TokenURL     string
	ClientID     string
	ClientSecret string
	HTTPClient   *uhttp.BaseHttpClient

	CustomHeaders     map[string]string
	CustomQueryParams map[string]string
}

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

func (b *BasicTokenSource) Token() (*oauth2.Token, error) {
	var requestOptions []uhttp.RequestOption
	client := b.HTTPClient
	logger := ctxzap.Extract(b.Ctx)
	logger.Debug("requesting Token via basic token source")

	u, err := url.Parse(b.TokenURL)
	if err != nil {
		return nil, err
	}

	// Adds custom headers
	if b.CustomHeaders != nil {
		logger.Debug("custom headers found", zap.Int("headers", len(b.CustomHeaders)))
		for k, v := range b.CustomHeaders {
			requestOptions = append(requestOptions, uhttp.WithHeader(k, v))
		}
	}

	// Adds custom Query params
	if b.CustomQueryParams != nil {
		q := u.Query()
		logger.Debug("custom headers found", zap.Int("headers", len(b.CustomQueryParams)))
		for k, v := range b.CustomQueryParams {
			q.Set(k, v)
		}
		u.RawQuery = q.Encode()
	}

	// Since this is intended as 'Request Token with basic auth', basic auth header gets included.
	requestOptions = append(requestOptions, uhttp.WithHeader("Authorization", "Basic "+basicAuth(b.ClientID, b.ClientSecret)))

	req, err := b.HTTPClient.NewRequest(
		b.Ctx,
		http.MethodGet,
		u,
		requestOptions...,
	)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, &oauth2.RetrieveError{
			Response: resp,
			Body:     body,
		}
	}

	var res struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
		TokenType   string `json:"token_type,omitempty"`
	}

	if err := json.Unmarshal(body, &res); err != nil {
		return nil, err
	}

	token := &oauth2.Token{
		AccessToken: res.AccessToken,
		TokenType:   res.TokenType,
		Expiry:      time.Now().Add(time.Duration(res.ExpiresIn) * time.Second),
	}

	return token, nil
}
