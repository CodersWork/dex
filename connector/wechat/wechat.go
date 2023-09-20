// Package wechat provides authentication strategies using Wechat.
package wechat

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"golang.org/x/oauth2"

	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/pkg/httpclient"
	"github.com/dexidp/dex/pkg/log"
)

const (
	// wechat scope support "openid" or "openid corpid"
	// https://open.wechat.com/document/orgapp-server/obtain-identity-credentials
	scopeOpenID = "snsapi_login"
)

// Config holds configuration options for wechat logins.
type Config struct {
	BaseURL      string   `json:"baseURL"`
	AppID        string   `json:"appID"`
	AppSecret    string   `json:"appSecret"`
	AppID2       string   `json:"appID2"`
	AppSecret2   string   `json:"appSecret2"`
	RedirectURI  string   `json:"redirectURI"`
	Groups       []string `json:"groups"`
	UseLoginAsID bool     `json:"useLoginAsID"`
}

type wechatUser struct {
	Nick      string `json:"nickname"`
	UnionID   string `json:"unionId"`
	OpenID    string `json:"openId"`
	Mobile    string `json:"mobile"`
	Email     string `json:"email"`
	AvatarURL string `json:"headimgurl"`
}

// Open returns a strategy for logging in through Wechat.
func (c *Config) Open(id string, logger log.Logger) (connector.Connector, error) {
	if c.BaseURL == "" {
		c.BaseURL = "https://open.weixin.qq.com/connect/qrconnect?"
	}

	httpClient, err := httpclient.NewHTTPClient(nil, false)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %v", err)
	}

	return &wechatConnector{
		baseURL:      c.BaseURL,
		redirectURI:  c.RedirectURI,
		appID:        c.AppID,
		appSecret:    c.AppSecret,
		appID2:       c.AppID2,
		appSecret2:   c.AppSecret2,
		logger:       logger,
		groups:       c.Groups,
		useLoginAsID: c.UseLoginAsID,
		httpClient:   httpClient,
	}, nil
}

type connectorData struct {
	// Support Wechat's Access Tokens and Refresh tokens.
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

var (
	_ connector.CallbackConnector = (*wechatConnector)(nil)
	_ connector.RefreshConnector  = (*wechatConnector)(nil)
)

type wechatConnector struct {
	baseURL     string
	redirectURI string
	groups      []string
	appID       string
	appSecret   string
	appID2      string
	appSecret2  string
	logger      log.Logger
	httpClient  *http.Client
	// if set to true will use the user's handle rather than their numeric id as the ID
	useLoginAsID bool
}

func (c *wechatConnector) oauth2Config(scopes connector.Scopes) *oauth2.Config {
	wechatScopes := []string{scopeOpenID}

	wechatEndpoint := oauth2.Endpoint{
		AuthURL:  "https://open.weixin.qq.com/connect/qrconnect",
		TokenURL: "https://api.weixin.qq.com/sns/oauth2/access_token",
	}
	return &oauth2.Config{
		ClientID:     c.appID,
		ClientSecret: c.appSecret,
		Endpoint:     wechatEndpoint,
		Scopes:       wechatScopes,
		RedirectURL:  c.redirectURI,
	}
}

func (c *wechatConnector) LoginURL(scopes connector.Scopes, callbackURL, state string) (string, error) {
	if c.redirectURI != callbackURL {
		return "", fmt.Errorf("expected callback URL %s did not match the URL in the config %s", c.redirectURI, callbackURL)
	}
	var buf bytes.Buffer
	buf.WriteString(c.oauth2Config(scopes).Endpoint.AuthURL)
	v := url.Values{
		"response_type": {"code"},
		"appid":         {c.oauth2Config(scopes).ClientID},
		"redirect_uri":  {c.oauth2Config(scopes).RedirectURL},
		"scope":         c.oauth2Config(scopes).Scopes,
	}
	if state != "" {
		v.Set("state", state)
	}
	buf.WriteByte('?')
	buf.WriteString(v.Encode())
	buf.WriteString("#wechat_redirect")
	return buf.String(), nil
}

type oauth2Error struct {
	error            string
	errorDescription string
}

func (e *oauth2Error) Error() string {
	if e.errorDescription == "" {
		return e.error
	}
	return e.error + ": " + e.errorDescription
}

type UserAccessTokenReq struct {
	ClientID     string `json:"appid"`
	ClientSecret string `json:"secret"`
	Code         string `json:"code"`
	RefreshToken string `json:"refreshToken"`
	GrantType    string `json:"grant_type"`
}

type UserAccessTokenResp struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpireIn     int    `json:"expire_in"`
	OpenID       string `json:"openid"`
	UnionID      string `json:"unionid"`
}

func (c *wechatConnector) HandleCallback(s connector.Scopes, r *http.Request) (identity connector.Identity, err error) {
	q := r.URL.Query()
	if errType := q.Get("error"); errType != "" {
		return identity, &oauth2Error{errType, q.Get("error_description")}
	}

	oauth2Config := c.oauth2Config(s)

	var v url.Values
	ctx := r.Context()
	if q.Has("wechat_app") {
		v = url.Values{
			"appid":      {c.appID2},
			"secret":     {c.appSecret2},
			"code":       {q.Get("code")},
			"grant_type": {"authorization_code"},
		}
	} else {
		v = url.Values{
			"appid":      {oauth2Config.ClientID},
			"secret":     {oauth2Config.ClientSecret},
			"code":       {q.Get("code")},
			"grant_type": {"authorization_code"},
		}
	}
	tokenURL, _ := url.Parse(oauth2Config.Endpoint.TokenURL)
	tokenURL.RawQuery = v.Encode()
	resp, err := c.httpClient.Get(tokenURL.String())
	if err != nil {
		c.logger.Errorf("in handlecallbak get token from [%s] get err[%v]", oauth2Config.Endpoint.TokenURL, err)
		return identity, fmt.Errorf("resp failed to get token: %v", err)
	}
	if resp.StatusCode == http.StatusOK {
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return identity, fmt.Errorf("read response body get err: %v", err)
		}

		respToken := UserAccessTokenResp{}
		json.Unmarshal(respBody, &respToken)

		return c.identity(ctx, s, respToken.AccessToken)
	}
	return identity, fmt.Errorf("wechat: failed to get token, http status code: %v", resp.StatusCode)
}

func (c *wechatConnector) identity(ctx context.Context, s connector.Scopes, token string) (identity connector.Identity, err error) {
	oauth2Config := c.oauth2Config(s)

	v := url.Values{
		"access_token": {token},
		"openid":       {oauth2Config.ClientID},
	}
	userInfoURL, _ := url.Parse("https://api.weixin.qq.com/sns/userinfo")
	userInfoURL.RawQuery = v.Encode()
	resp, err := c.httpClient.Get(userInfoURL.String())
	if err != nil {
		c.logger.Errorf("in handlecallbak get userInfo err[%v]", err)
		return identity, fmt.Errorf("resp failed to get userInfo: %v", err)
	}

	if resp.StatusCode == http.StatusOK {
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return identity, fmt.Errorf("read response body get err: %v", err)
		}

		var user wechatUser
		json.Unmarshal(respBody, &user)

		// if user do not have a email address, use mobile number instead.
		email := user.Email
		if email == "" {
			email = user.UnionID + "@WeChat"
		}

		identity = connector.Identity{
			UserID:            user.UnionID,
			Username:          user.Nick,
			PreferredUsername: user.Nick,
			Email:             email,
			EmailVerified:     true,
		}
		return identity, nil
	}
	return identity, fmt.Errorf("failed to get userInfo http Status Code %v", resp.StatusCode)
}

func (c *wechatConnector) Refresh(ctx context.Context, s connector.Scopes, ident connector.Identity) (connector.Identity, error) {
	var data connectorData
	if err := json.Unmarshal(ident.ConnectorData, &data); err != nil {
		return ident, fmt.Errorf("wechat: unmarshal connector data: %v", err)
	}
	oauth2Config := c.oauth2Config(s)

	switch {
	case data.RefreshToken != "":
		{
			reqBody := UserAccessTokenReq{
				ClientID:     oauth2Config.ClientID,
				ClientSecret: oauth2Config.ClientSecret,
				RefreshToken: data.RefreshToken,
				GrantType:    "refresh_token",
			}
			body, _ := json.Marshal(reqBody)
			resp, err := http.Post(oauth2Config.Endpoint.TokenURL, "application/json", bytes.NewBuffer(body))
			if err != nil {
				return ident, fmt.Errorf("refresh token resp failed to get token: %v", err)
			}

			if resp.StatusCode == http.StatusOK {
				respBody, err := io.ReadAll(resp.Body)
				if err != nil {
					return ident, fmt.Errorf("refresh token read response body get err: %v", err)
				}

				respToken := UserAccessTokenResp{}
				json.Unmarshal(respBody, &respToken)
			}
			return c.identity(ctx, s, "")
		}
	case data.AccessToken != "":
		{
			token := &oauth2.Token{
				AccessToken: data.AccessToken,
			}
			return c.identity(ctx, s, token.AccessToken)
		}
	default:
		return ident, errors.New("no refresh or access token found")
	}
}
