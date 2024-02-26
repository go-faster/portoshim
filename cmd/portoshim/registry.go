package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"go.uber.org/zap"
)

type RegistryInfo struct {
	Host        string `yaml:"Host"`
	AuthToken   string `yaml:"AuthToken"`
	AuthPath    string `yaml:"AuthPath"`
	AuthService string `yaml:"AuthService"`
}

const (
	defaultDockerRegistry = "registry-1.docker.io"
)

var KnownRegistries = map[string]RegistryInfo{
	defaultDockerRegistry: {
		Host: defaultDockerRegistry,
	},
	"quay.io": {
		Host:     "quay.io",
		AuthPath: "https://quay.io/v2/auth",
	},
}

func InitKnownRegistries() error {
	for _, info := range Cfg.Images.Registries {
		zap.S().Infof("add registry from config %+v", info)
		KnownRegistries[info.Host] = info
	}

	for host, registry := range KnownRegistries {
		if strings.HasPrefix(registry.AuthToken, "file:") {
			authTokenPath := registry.AuthToken[5:]
			// if file doesn't exist then auth token is empty
			_, err := os.Stat(authTokenPath)
			if err != nil {
				if os.IsNotExist(err) {
					registry.AuthToken = ""
				} else {
					return err
				}
			} else {
				content, err := os.ReadFile(authTokenPath)
				if err != nil {
					return err
				}
				registry.AuthToken = strings.TrimSpace(string(content))
			}
			KnownRegistries[host] = registry
		}
	}

	return nil
}

func InitAuths() error {
	const defaultAuthsFile = "/etc/portoshim/auths.json"
	authsPath := Cfg.Images.AuthsFile
	if authsPath == "" {
		// Path is not present in config.
		if _, err := os.Stat(defaultAuthsFile); err != nil {
			// Default location does not exist either.
			return nil
		}
		authsPath = defaultAuthsFile
	}
	zap.S().Debugw("Reading auths", "path", authsPath)

	data, err := os.ReadFile(authsPath)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(data, &Cfg.Images.AuthCfg); err != nil {
		return fmt.Errorf("parse auths from %q: %w", authsPath, err)
	}
	auths := Cfg.Images.AuthCfg.Auths
	for prefix, cfg := range auths {
		if cfg.Auth == "" {
			continue
		}

		cfg.Username, cfg.Password, err = decodeAuth(cfg.Auth)
		if err != nil {
			return fmt.Errorf("parse auths %q: %w", prefix, err)
		}

		auths[prefix] = cfg
	}

	return nil
}

// decodeAuth decodes a base64 encoded string and returns username and password
func decodeAuth(authStr string) (string, string, error) {
	if authStr == "" {
		return "", "", nil
	}

	decLen := base64.StdEncoding.DecodedLen(len(authStr))
	decoded := make([]byte, decLen)
	authByte := []byte(authStr)
	n, err := base64.StdEncoding.Decode(decoded, authByte)
	if err != nil {
		return "", "", err
	}
	if n > decLen {
		return "", "", fmt.Errorf("something went wrong decoding auth config")
	}
	userName, password, ok := strings.Cut(string(decoded), ":")
	if !ok || userName == "" {
		return "", "", fmt.Errorf("invalid auth configuration file")
	}
	return userName, strings.Trim(password, "\x00"), nil
}

func GetImageRegistry(name string) RegistryInfo {
	host := defaultDockerRegistry

	slashPos := strings.Index(name, "/")
	if slashPos > -1 {
		host = name[:slashPos]
	}

	if registry, ok := KnownRegistries[host]; ok {
		return registry
	}

	return RegistryInfo{}
}
