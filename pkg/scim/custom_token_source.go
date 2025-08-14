package scim

/*
	CUSTOM TOKEN SOURCE
	  Because SCIM APIs may differ in how Bearer tokens are requested, this custom token source allows
	  users to specify the exact method for obtaining new tokens.

	FAQs
    	- WHEN SHOULD I USE THIS?
    		Use this when your SCIM API requires a custom method for requesting Bearer tokens that isn't supported by the standard TokenSource.
			ATM this implementation doesn't support specific scopes for the token.

    	- IS THIS REALLY NECESSARY?
    		In some cases, yes. This feature enables baton-scim to work with SCIM APIs that have unique requirements for how tokens must be requested.
*/

import (
	"context"
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

type CustomTokenSource struct {
	Ctx          context.Context
	TokenURL     string
	ClientID     string
	ClientSecret string
	HTTPClient   *uhttp.BaseHttpClient

	ContentType          string
	CustomHeaders        map[string]string
	CustomQueryParams    map[string]string
	CustomFormBodyValues map[string]string
}

func (b *CustomTokenSource) Token() (*oauth2.Token, error) {
	logger := ctxzap.Extract(b.Ctx)
	logger.Debug("requesting Token via custom token source")

	var requestOptions []uhttp.RequestOption
	client := b.HTTPClient

	u, err := url.Parse(b.TokenURL)
	if err != nil {
		return nil, err
	}

	// Adds custom headers.
	if b.CustomHeaders != nil {
		logger.Debug("custom headers found", zap.Int("headers", len(b.CustomHeaders)))

		for k, v := range b.CustomHeaders {
			requestOptions = append(requestOptions, uhttp.WithHeader(k, v))
		}
	}

	// Adds custom query params.
	if b.CustomQueryParams != nil {
		logger.Debug("custom query params found", zap.Int("query params", len(b.CustomQueryParams)))

		q := u.Query()
		for k, v := range b.CustomQueryParams {
			q.Set(k, v)
		}
		u.RawQuery = q.Encode()
	}

	// Adds form body.
	if b.CustomFormBodyValues != nil {
		logger.Debug("custom form body values found", zap.Int("values", len(b.CustomFormBodyValues)))

		vals := url.Values{}
		for k, v := range b.CustomFormBodyValues {
			vals.Set(k, v)
		}

		form := vals.Encode()
		requestOptions = append(requestOptions, uhttp.WithFormBody(form))
	}

	if b.ContentType == "" {
		logger.Debug("no custom content type found. Setting 'application/json' by default.")
		b.ContentType = "application/json"
	}
	logger.Debug("custom content type found", zap.String("content type", b.ContentType))
	requestOptions = append(requestOptions, uhttp.WithContentType(b.ContentType))

	req, err := b.HTTPClient.NewRequest(
		b.Ctx,
		http.MethodPost,
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
