package libstns

import (
	"github.com/BurntSushi/toml"
	"github.com/panda-lab/libnss_stns/settings"
)

type Config struct {
	ApiEndPoint     []string          `toml:"api_end_point"`
	AuthToken       string            `toml:"auth_token"`
	RequestTimeOut  int               `toml:"request_timeout"`
	RequestRetry    int               `toml:"retry_request"`
	User            string            `toml:"user"`
	Password        string            `toml:"password"`
	SslVerify       bool              `toml:"ssl_verify"`
	WrapperCommand  string            `toml:"wrapper_path"`
	ChainSshWrapper string            `toml:"chain_ssh_wrapper"`
	HttpProxy       string            `toml:"http_proxy"`
	RequestHeader   map[string]string `toml:"request_header"`
	TlsCa           string            `toml:"tls_ca"`
	TlsCert         string            `toml:"tls_cert"`
	TlsKey          string            `toml:"tls_key"`
	UIDShift        int               `toml:"uid_shift"`
	GIDShift        int               `toml:"gid_shift"`
}

func LoadConfig(filePath string) (*Config, error) {
	var config Config

	defaultConfig(&config)
	_, err := toml.DecodeFile(filePath, &config)
	if err != nil {
		return nil, err
	}
	return &config, nil
}

func defaultConfig(config *Config) {
	config.RequestTimeOut = settings.HTTP_TIMEOUT
	config.RequestRetry = 3
	config.WrapperCommand = "/usr/local/bin/stns-query-wrapper"
	config.ApiEndPoint = []string{"http://localhost:1104"}
	config.UIDShift = 0
	config.GIDShift = 0
}
