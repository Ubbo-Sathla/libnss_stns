package libstns

import (
	"testing"

	"github.com/panda-lab/libnss_stns/test"
)

func TestLoadConfig(t *testing.T) {
	config, err := LoadConfig("./fixtures/config/test_config_001.conf")
	test.AssertNoError(t, err)
	test.Assert(t, config.ApiEndPoint[0] == "http://api01.example.com", "ng api endpoint1")
	test.Assert(t, config.ApiEndPoint[1] == "http://api02.example.com", "ng api endpoint2")
	test.Assert(t, config.RequestHeader["x-api-key"] == "fuga", "ng request header")
	test.Assert(t, config.TlsCa == "ca.pem", "unmatch tls ca")
	test.Assert(t, config.TlsCert == "tls.crt", "unmatch tls crt")
	test.Assert(t, config.TlsKey == "tls.key", "unmatch tls key")
	test.Assert(t, config.RequestRetry == 3, "ng request retry")
	test.Assert(t, config.UIDShift == -1000, "unmatch uid shift")
	test.Assert(t, config.GIDShift == -2000, "unmatch gid shift")
}
