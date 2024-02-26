package main

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v2"
)

type PortoshimConfig struct {
	Portoshim struct {
		ConfigPath string `yaml:"ConfigPath"`
		Socket     string `yaml:"Socket"`
		LogsDir    string `yaml:"LogsDir"`
		VolumesDir string `yaml:"VolumesDir"`
	} `yaml:"Portoshim"`

	Porto struct {
		RuntimeName   string        `yaml:"RuntimeName"`
		Socket        string        `yaml:"Socket"`
		SocketTimeout time.Duration `yaml:"SocketTimeout"`
		ImagesDir     string        `yaml:"ImagesDir"`
	} `yaml:"Porto"`

	CNI struct {
		ConfDir        string `yaml:"ConfDir"`
		BinDir         string `yaml:"BinDir"`
		NetnsDir       string `yaml:"NetnsDir"`
		ConfigTemplate string `yaml:"ConfigTemplate"`
	} `yaml:"CNI"`

	StreamingServer struct {
		Address string `yaml:"Address"`
		Port    int    `yaml:"Port"`
	} `yaml:"StreamingServer"`

	Images struct {
		PauseImage     string         `yaml:"PauseImage"`
		PullPauseImage bool           `yaml:"PullPauseImage"`
		Registries     []RegistryInfo `yaml:"Registries"`
		AuthsFile      string         `yaml:"AuthsFile"`
		AuthCfg        Auths          `yaml:"-"`
	} `yaml:"Images"`
}

type Auths struct {
	Auths       map[string]AuthConfig `json:"auths,omitempty"`
	HTTPHeaders map[string]string     `json:"HttpHeaders,omitempty"`
}

type AuthConfig struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Auth     string `json:"auth,omitempty"`

	ServerAddress string `json:"serveraddress,omitempty"`

	// IdentityToken is used to authenticate the user and get
	// an access token for the registry.
	IdentityToken string `json:"identitytoken,omitempty"`

	// RegistryToken is a bearer token to be sent to a registry
	RegistryToken string `json:"registrytoken,omitempty"`
}

var defaultConfig = `
Portoshim:
    ConfigPath: /etc/portoshim.yaml
    Socket:     /run/portoshim.sock
    LogsDir:    /var/log/portoshim
    VolumesDir: /place/portoshim_volumes
Porto:
    RuntimeName: porto
    Socket:      /run/portod.socket
    SocketTimeout: 5m
    ImagesDir:   /place/porto_docker
CNI:
    ConfDir:  /etc/cni/net.d
    BinDir:   /opt/cni/bin
    NetnsDir: /var/run/netns
StreamingServer:
    Address: "[::]"
    Port:    7255
Images:
    PauseImage: registry.k8s.io/pause:3.7
    PullPauseImage: true
`

var Cfg *PortoshimConfig

func InitConfig(configPath string) error {
	var err error

	// set default values
	if err = yaml.Unmarshal([]byte(defaultConfig), &Cfg); err != nil {
		return fmt.Errorf("%s: %v", getCurrentFuncName(), err)
	}

	_, err = os.Stat(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			// try using default config path
			if Cfg.Portoshim.ConfigPath == configPath {
				// already check default config path
				return nil
			}
			_, err = os.Stat(Cfg.Portoshim.ConfigPath)
			if err != nil {
				if os.IsNotExist(err) {
					return nil
				} else {
					return err
				}
			}
		} else {
			return err
		}
	} else {
		// custom config path exists, so use it
		Cfg.Portoshim.ConfigPath = configPath
	}

	data, err := os.ReadFile(Cfg.Portoshim.ConfigPath)
	if err != nil {
		return fmt.Errorf("%s: %v", getCurrentFuncName(), err)
	}

	if err = yaml.Unmarshal(data, &Cfg); err != nil {
		return fmt.Errorf("%s: %v", getCurrentFuncName(), err)
	}

	return nil
}
