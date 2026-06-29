package client

import (
	"context"
	"net/http"
)

type BaseClient struct {
	HttpClient    *http.Client
	JwtHttpClient *http.Client

	AccessToken  string
	RefreshToken string
	Initialized  bool
	WithRetry    bool
}

func NewBaseClient() *BaseClient {
	httpClient := &http.Client{}
	jwtHttpClient := &http.Client{}

	return &BaseClient{
		HttpClient:    httpClient,
		JwtHttpClient: jwtHttpClient,
	}
}

func (c *BaseClient) Reset() {
	c.HttpClient = &http.Client{}
	c.JwtHttpClient = &http.Client{}
	c.AccessToken = ""
	c.RefreshToken = ""
	c.Initialized = false
	c.WithRetry = false
}

func (a *BaseClient) AddJWTToHeader(_ context.Context, req *http.Request) error {
	req.Header.Add("Authorization", "Bearer "+a.AccessToken)

	return nil
}
