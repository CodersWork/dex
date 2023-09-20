// Package dingtalk provides authentication strategies using Dingtalk.
package dingtalk

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/pkg/httpclient"
	"github.com/dexidp/dex/pkg/log"
)

const (
	// dingtalk scope support "openid" or "openid corpid"
	// https://open.dingtalk.com/document/orgapp-server/obtain-identity-credentials
	scopeOpenID = "openid"
)

// Config holds configuration options for dingtalk logins.
type Config struct {
	BaseURL      string   `json:"baseURL"`
	AppID        string   `json:"appID"`
	AppSecret    string   `json:"appSecret"`
	RedirectURI  string   `json:"redirectURI"`
	Groups       []string `json:"groups"`
	UseLoginAsID bool     `json:"useLoginAsID"`
}

type dingtalkUser struct {
	Nick      string `json:"nick"`
	UnionID   string `json:"unionId"`
	OpenID    string `json:"openId"`
	Mobile    string `json:"mobile"`
	StateCode string `json:"stateCode"`
	Email     string `json:"email"`
}

// Open returns a strategy for logging in through Dingtalk.
func (c *Config) Open(id string, logger log.Logger) (connector.Connector, error) {
	if c.BaseURL == "" {
		c.BaseURL = "https://api.dingtalk.com"
	}

	httpClient, err := httpclient.NewHTTPClient(nil, false)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %v", err)
	}

	return &dingtalkConnector{
		baseURL:      c.BaseURL,
		redirectURI:  c.RedirectURI,
		appID:        c.AppID,
		appSecret:    c.AppSecret,
		logger:       logger,
		groups:       c.Groups,
		useLoginAsID: c.UseLoginAsID,
		httpClient:   httpClient,
	}, nil
}

type connectorData struct {
	// Support Dingtalk's Access Tokens and Refresh tokens.
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

var (
	_ connector.CallbackConnector = (*dingtalkConnector)(nil)
	_ connector.RefreshConnector  = (*dingtalkConnector)(nil)
)

type dingtalkConnector struct {
	baseURL     string
	redirectURI string
	groups      []string
	appID       string
	appSecret   string
	logger      log.Logger
	httpClient  *http.Client
	// if set to true will use the user's handle rather than their numeric id as the ID
	useLoginAsID bool
	accessToken  string
}

func (c *dingtalkConnector) oauth2Config(scopes connector.Scopes) *oauth2.Config {
	dingtalkScopes := []string{scopeOpenID}

	dingtalkEndpoint := oauth2.Endpoint{
		AuthURL:  "https://login.dingtalk.com/oauth2/auth",
		TokenURL: c.baseURL + "/v1.0/oauth2/userAccessToken",
	}
	return &oauth2.Config{
		ClientID:     c.appID,
		ClientSecret: c.appSecret,
		Endpoint:     dingtalkEndpoint,
		Scopes:       dingtalkScopes,
		RedirectURL:  c.redirectURI,
	}
}

func (c *dingtalkConnector) LoginURL(scopes connector.Scopes, callbackURL, state string) (string, error) {
	if c.redirectURI != callbackURL {
		return "", fmt.Errorf("expected callback URL %s did not match the URL in the config %s", c.redirectURI, callbackURL)
	}
	var opts []oauth2.AuthCodeOption
	if scopes.OfflineAccess {
		opts = append(opts, oauth2.AccessTypeOffline, oauth2.SetAuthURLParam("prompt", "consent"))
	}
	return c.oauth2Config(scopes).AuthCodeURL(state, opts...), nil
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
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
	Code         string `json:"code"`
	RefreshToken string `json:"refreshToken"`
	GrantType    string `json:"grantType"`
}

type UserAccessTokenResp struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	ExpireIn     int    `json:"expireIn"`
}

func (c *dingtalkConnector) HandleCallback(s connector.Scopes, r *http.Request) (identity connector.Identity, err error) {
	q := r.URL.Query()
	if errType := q.Get("error"); errType != "" {
		return identity, &oauth2Error{errType, q.Get("error_description")}
	}

	if q.Has("ios_app") {
		return c.identityByiOS(q.Get("authCode"))
	}
	oauth2Config := c.oauth2Config(s)

	var token oauth2.Token

	ctx := r.Context()
	reqBody := UserAccessTokenReq{
		ClientID:     oauth2Config.ClientID,
		ClientSecret: oauth2Config.ClientSecret,
		Code:         q.Get("authCode"),
		RefreshToken: q.Get("state"),
		GrantType:    "authorization_code",
	}
	body, _ := json.Marshal(reqBody)
	resp, err := c.httpClient.Post(oauth2Config.Endpoint.TokenURL, "application/json", bytes.NewBuffer(body))
	if err != nil {
		c.logger.Errorf("in handlecallbak get token from [%s] reqBody is [%s] get err[%v]", oauth2Config.Endpoint.TokenURL, string(body), err)
		return identity, fmt.Errorf("resp failed to get token: %v", err)
	}
	if resp.StatusCode == http.StatusOK {
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return identity, fmt.Errorf("read response body get err: %v", err)
		}

		respToken := UserAccessTokenResp{}
		json.Unmarshal(respBody, &respToken)

		token = oauth2.Token{
			AccessToken:  respToken.AccessToken,
			RefreshToken: respToken.RefreshToken,
			Expiry:       time.Now().Add(time.Second * time.Duration(respToken.ExpireIn)),
		}
	}
	return c.identity(ctx, s, &token)
}

func (c *dingtalkConnector) identity(ctx context.Context, s connector.Scopes, token *oauth2.Token) (identity connector.Identity, err error) {
	oauth2Config := c.oauth2Config(s)

	// if c.httpClient != nil {
	// 	ctx = context.WithValue(ctx, oauth2.HTTPClient, c.httpClient)
	// }

	client := oauth2Config.Client(ctx, token)

	user, err := c.user(ctx, c.httpClient, token)
	if err != nil {
		c.logger.Errorf("in identity get user by ctx [%v] client is [%v] token is[%v]", ctx, client, token)
		return identity, fmt.Errorf("dingtalk: get user: %v", err)
	}

	// mobile number is required rather than email address in Dingtalk
	// if user do not have a email address, use mobile number instead.
	email := user.Email
	if email == "" {
		email = user.Mobile + "@Dingtalk"
	}

	identity = connector.Identity{
		UserID:            user.UnionID,
		Username:          user.Nick,
		PreferredUsername: user.Nick,
		Email:             email,
		EmailVerified:     true,
	}
	if c.useLoginAsID {
		identity.UserID = user.Mobile
	}

	if c.groupsRequired(s.Groups) {
		groups, err := c.getGroups(ctx, client, s.Groups, user.Mobile)
		if err != nil {
			return identity, fmt.Errorf("dingtalk: get groups: %v", err)
		}
		identity.Groups = groups
	}

	//TODO: This is only a temporary solution, we need to find a better way to get the user's organization
	identity.Groups = append([]string{"吉大正元"}, identity.Groups...)

	if s.OfflineAccess {
		data := connectorData{RefreshToken: token.RefreshToken, AccessToken: token.AccessToken}
		connData, err := json.Marshal(data)
		if err != nil {
			return identity, fmt.Errorf("dingtalk: marshal connector data: %v", err)
		}
		identity.ConnectorData = connData
	}

	return identity, nil
}

func (c *dingtalkConnector) Refresh(ctx context.Context, s connector.Scopes, ident connector.Identity) (connector.Identity, error) {
	var data connectorData
	if err := json.Unmarshal(ident.ConnectorData, &data); err != nil {
		return ident, fmt.Errorf("dingtalk: unmarshal connector data: %v", err)
	}
	oauth2Config := c.oauth2Config(s)

	switch {
	case data.RefreshToken != "":
		{
			var token oauth2.Token

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
				token = oauth2.Token{
					AccessToken:  respToken.AccessToken,
					RefreshToken: respToken.RefreshToken,
					Expiry:       time.Now().Add(time.Second * time.Duration(respToken.ExpireIn)),
				}
			}
			return c.identity(ctx, s, &token)
		}
	case data.AccessToken != "":
		{
			token := &oauth2.Token{
				AccessToken: data.AccessToken,
			}
			return c.identity(ctx, s, token)
		}
	default:
		return ident, errors.New("no refresh or access token found")
	}
}

func (c *dingtalkConnector) groupsRequired(groupScope bool) bool {
	return len(c.groups) > 0 || groupScope
}

// The HTTP native oauth client is  constructed by the golang.org/x/oauth2 package, which inserts
// a bearer token as part of the request.
// Dingtalk use a x-acs-dingtalk-access-token header instead of bearer token.
// so we can't use oauth2.HTTPClient
func (c *dingtalkConnector) user(ctx context.Context, client *http.Client, token *oauth2.Token) (dingtalkUser, error) {
	var u dingtalkUser
	req, err := http.NewRequest("GET", c.baseURL+"/v1.0/contact/users/me", nil)
	if err != nil {
		return u, fmt.Errorf("dingtalk: new req: %v", err)
	}
	req.Header.Set("x-acs-dingtalk-access-token", token.AccessToken)

	req = req.WithContext(ctx)
	resp, err := client.Do(req)
	if err != nil {
		c.logger.Errorf("client.Do return err is [%v]", err)
		return u, fmt.Errorf("dingtalk: get URL %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return u, fmt.Errorf("dingtalk: read body: %v", err)
		}
		return u, fmt.Errorf("%s: %s", resp.Status, body)
	}
	if err := json.NewDecoder(resp.Body).Decode(&u); err != nil {
		return u, fmt.Errorf("failed to decode response: %v", err)
	}
	return u, nil
}

// TODO implement group feature by corpid
// corpid scope refer: https://open.dingtalk.com/document/orgapp/obtain-identity-credentials
func (c *dingtalkConnector) getGroups(ctx context.Context, client *http.Client, groupScope bool, userLogin string) ([]string, error) {
	return nil, nil
}

func (c *dingtalkConnector) identityByiOS(authCode string) (identity connector.Identity, err error) {
	err = c.GetAccesstoken()
	if err != nil {
		return identity, err
	}
	unionid, err := c.GetUnionIDByCode(authCode)
	if err != nil {
		return identity, err
	}
	userid, err := c.GetUserIDByUnionID(unionid)
	if err != nil {
		return identity, err
	}

	urlEndpoint, err := url.Parse("https://oapi.dingtalk.com/topapi/v2/user/get")
	if err != nil {
		return identity, err
	}

	query := url.Values{}
	query.Set("access_token", c.accessToken)

	urlEndpoint.RawQuery = query.Encode()
	urlPath := urlEndpoint.String()

	resp, err := http.PostForm(urlPath, url.Values{"userid": {userid}})
	if err != nil {
		return identity, err
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return identity, err
	}

	var rdata map[string]interface{}
	err = json.Unmarshal(body, &rdata)
	if err != nil {
		return identity, err
	}

	errcode := rdata["errcode"].(float64)
	if errcode != 0 {
		return identity, fmt.Errorf("登录错误: %.0f, %s", errcode, rdata["errmsg"].(string))
	}

	userinfo := rdata["result"].(map[string]interface{})
	username := userinfo["name"].(string)
	email := userinfo["mobile"].(string) + "@DingTalk"

	identity = connector.Identity{
		UserID:            unionid,
		Username:          username,
		PreferredUsername: username,
		Email:             email,
		EmailVerified:     true,
	}
	identity.Groups = append([]string{"吉大正元"}, identity.Groups...)
	return identity, nil
}
func (c *dingtalkConnector) GetUserIDByUnionID(unionid string) (string, error) {
	urlEndpoint, err := url.Parse("https://oapi.dingtalk.com/topapi/user/getbyunionid")
	if err != nil {
		return "", err
	}

	query := url.Values{}
	query.Set("access_token", c.accessToken)
	urlEndpoint.RawQuery = query.Encode()
	urlPath := urlEndpoint.String()

	resp, err := http.PostForm(urlPath, url.Values{"unionid": {unionid}})
	if err != nil {
		return "", err
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	var rdata map[string]interface{}
	err = json.Unmarshal(body, &rdata)
	if err != nil {
		return "", err
	}

	errcode := rdata["errcode"].(float64)
	if errcode != 0 {
		return "", fmt.Errorf("登录错误: %.0f, %s", errcode, rdata["errmsg"].(string))
	}

	result := rdata["result"].(map[string]interface{})
	if result["contact_type"].(float64) != 0 {
		return "", errors.New("该用户不属于企业内部员工，无法登录。")
	}
	userid := result["userid"].(string)
	return userid, nil
}

func (c *dingtalkConnector) GetAccesstoken() (err error) {

	url := fmt.Sprintf("https://oapi.dingtalk.com/gettoken?appkey=%s&appsecret=%s", c.appID, c.appSecret)
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var i map[string]interface{}
	err = json.Unmarshal(body, &i)
	if err != nil {
		return err
	}

	if i["errcode"].(float64) == 0 {
		c.accessToken = i["access_token"].(string)
		return nil
	}
	return errors.New("accesstoken获取错误:" + i["errmsg"].(string))
}

func (c *dingtalkConnector) GetUnionIDByCode(code string) (string, error) {
	var resp *http.Response
	//服务端通过临时授权码获取授权用户的个人信息
	timestamp := strconv.FormatInt(time.Now().UnixNano()/1000000, 10) // 毫秒时间戳
	signature := c.getSignature(timestamp)
	urlPath := fmt.Sprintf(
		"https://oapi.dingtalk.com/sns/getuserinfo_bycode?accessKey=%s&timestamp=%s&signature=%s",
		c.appID, timestamp, signature)

	param := struct {
		Tmp_auth_code string `json:"tmp_auth_code"`
	}{code}
	paraByte, _ := json.Marshal(param)
	paraString := string(paraByte)

	resp, err := http.Post(urlPath, "application/json;charset=UTF-8", strings.NewReader(paraString))
	if err != nil {
		return "", err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var rdata map[string]interface{}
	err = json.Unmarshal(body, &rdata)
	if err != nil {
		return "", err
	}
	errcode := rdata["errcode"].(float64)
	if errcode != 0 {
		return "", fmt.Errorf("登录错误: %.0f, %s", errcode, rdata["errmsg"].(string))
	}
	unionid := rdata["user_info"].(map[string]interface{})["unionid"].(string)
	return unionid, nil
}

// 钉钉签名算法实现
func (c *dingtalkConnector) getSignature(timestamp string) string {
	h := hmac.New(sha256.New, []byte(c.appSecret))
	h.Write([]byte(timestamp))
	sum := h.Sum(nil) // 二进制流
	tmpMsg := base64.StdEncoding.EncodeToString(sum)

	uv := url.Values{}
	uv.Add("0", tmpMsg)

	return uv.Encode()[2:]
}
