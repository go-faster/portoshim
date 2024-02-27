package main

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/containerd/containerd/remotes/docker/auth"
	"github.com/distribution/reference"
	v1 "k8s.io/cri-api/pkg/apis/runtime/v1"
)

func getRegistryToken(ctx context.Context, img string, reqAuthCfg *v1.AuthConfig) (_ string, err error) {
	authCfg := AuthConfig{
		// Getters are nil-safe.
		Username:      reqAuthCfg.GetUsername(),
		Password:      reqAuthCfg.GetPassword(),
		Auth:          reqAuthCfg.GetAuth(),
		IdentityToken: reqAuthCfg.GetIdentityToken(),
		RegistryToken: reqAuthCfg.GetRegistryToken(),
	}
	if authStr := authCfg.Auth; authStr != "" {
		authCfg.Username, authCfg.Password, err = decodeAuth(authStr)
		if err != nil {
			return "", fmt.Errorf("parse request auth: %w", err)
		}
	}

	if authCfg == (AuthConfig{}) {
		// In case if request auth config is not present, try to get one from config.
		for prefix, cfg := range Cfg.Images.AuthCfg.Auths {
			if !strings.HasPrefix(img, prefix) {
				continue
			}
			DebugLog(ctx, "Using auth config %q to pull %q", prefix, img)
			authCfg = cfg
			break
		}
	} else {
		DebugLog(ctx, "Using auth config from request to pull %q", img)
	}

	// Prefer defined registry token.
	if t := authCfg.RegistryToken; t != "" {
		return "Bearer " + t, nil
	}
	var (
		username = authCfg.Username
		secret   = authCfg.IdentityToken
		headers  http.Header
	)
	if secret == "" {
		secret = authCfg.Password
	}
	if h := Cfg.Images.AuthCfg.HTTPHeaders; len(h) > 0 {
		headers = http.Header{}
		for name, value := range h {
			headers.Set(name, value)
		}
	}

	client := http.DefaultClient
	challenges, err := fetchAuthHeader(ctx, client, img)
	if err != nil {
		return "", fmt.Errorf("fetch auth header: %w", err)
	}

	for _, h := range challenges {
		if h.Scheme != auth.BearerAuth {
			DebugLog(ctx, "Skipping auth scheme %q", h.Scheme)
			continue
		}

		var (
			realm   = h.Parameters["realm"]
			service = h.Parameters["service"]
			scopes  []string
		)
		if scope, ok := h.Parameters["scope"]; ok {
			scopes = strings.Split(scope, " ")
		}

		resp, err := auth.FetchToken(ctx, client, headers, auth.TokenOptions{
			Realm:    realm,
			Service:  service,
			Scopes:   scopes,
			Username: username,
			Secret:   secret,
		})
		if err != nil {
			return "", fmt.Errorf("fetch token: %w", err)
		}
		DebugLog(ctx, "Got token (service: %q, realm: %q, scopes %#v)", service, realm, scopes)
		return "Bearer " + resp.Token, nil
	}

	return "", nil
}

func fetchAuthHeader(ctx context.Context, client *http.Client, img string) ([]auth.Challenge, error) {
	ref, err := reference.ParseNormalizedNamed(img)
	if err != nil {
		return nil, fmt.Errorf("parse reference %q: %w", img, err)
	}
	var digestOrTag string
	switch ref := ref.(type) {
	case reference.Digested:
		digestOrTag = ref.Digest().String()
	case reference.Tagged:
		digestOrTag = ref.Tag()
	default:
		digestOrTag = "latest"
	}

	manifestURL := (&url.URL{
		Scheme: "https",
		Host:   reference.Domain(ref),
	}).JoinPath(
		"v2",
		reference.Path(ref),
		"manifests",
		digestOrTag,
	).String()

	DebugLog(ctx, "Trying to fetch manifest %s", manifestURL)
	resp, err := get(ctx, client, manifestURL)
	if err != nil {
		return nil, fmt.Errorf("get manifest: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	DebugLog(ctx, "Manifest %s fetch result: %d", manifestURL, resp.StatusCode)
	return auth.ParseAuthHeader(resp.Header), nil
}

func get(ctx context.Context, client *http.Client, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}
	return resp, nil
}
