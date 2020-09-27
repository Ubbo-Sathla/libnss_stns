package libstns

import (
	"fmt"
	"log"
	"strings"

	"github.com/panda-lab/libnss_stns/bcrypt_crypt"
	"github.com/panda-lab/libnss_stns/stns"
	"github.com/tredoe/osutil/user/crypt"
	"github.com/tredoe/osutil/user/crypt/apr1_crypt"
	"github.com/tredoe/osutil/user/crypt/md5_crypt"
	"github.com/tredoe/osutil/user/crypt/sha256_crypt"
	"github.com/tredoe/osutil/user/crypt/sha512_crypt"
)

const (
	PAM_AUTH_ERR         = 7
	PAM_AUTHINFO_UNAVAIL = 9
	PAM_SUCCESS          = 0
)

type Pam struct {
	config   *Config
	AuthType string
	argc     int
	argv     []string
}

func NewPam(config *Config, argc int, argv []string) *Pam {
	var u string
	u = "user"
	if argc > 0 {
		u = argv[0]
	}

	return &Pam{
		config:   config,
		AuthType: u,
		argc:     argc,
		argv:     argv,
	}
}

func (p *Pam) SudoUser() string {
	if p.argc > 1 {
		return p.argv[1]
	}
	return ""
}

func (p *Pam) PasswordAuth(user string, password string) int {
	r, err := NewRequest(p.config, fmt.Sprintf("/users?name=%s", user))
	log.Printf("%#v", r)
	if err != nil {
		log.Println(err)
		return PAM_AUTHINFO_UNAVAIL
	}
	res, err := r.GetByWrapperCmd()
	log.Println(res)
	if err != nil {
		log.Println(err)
		return PAM_AUTHINFO_UNAVAIL
	}

	if res.Items == nil {
		log.Printf("resource notfound %s/%s", p.AuthType, user)
		return PAM_AUTHINFO_UNAVAIL
	}

	var attr stns.Attribute
	for _, a := range res.Items {
		attr = a
		break
	}

	if strings.Count(attr.Password, "$") != 3 {
		return PAM_AUTHINFO_UNAVAIL
	}

	var c crypt.Crypter
	switch {
	case strings.HasPrefix(attr.Password, sha512_crypt.MagicPrefix):
		log.Println("sha512")
		c = sha512_crypt.New()
	case strings.HasPrefix(attr.Password, sha256_crypt.MagicPrefix):
		log.Println("sha256")
		c = sha256_crypt.New()
	case strings.HasPrefix(attr.Password, md5_crypt.MagicPrefix):
		log.Println("md5")
		c = md5_crypt.New()
	case strings.HasPrefix(attr.Password, apr1_crypt.MagicPrefix):
		log.Println("apr1")
		c = apr1_crypt.New()
	case strings.HasPrefix(attr.Password, bcrypt_crypt.MagicPrefix):
		c = bcrypt_crypt.New()

	}
	log.Println(attr.Password, password)
	err = c.Verify(attr.Password, []byte(password))
	if err == nil {
		log.Println("PAM_SUCCESS")
		return PAM_SUCCESS
	}

	return PAM_AUTH_ERR
}
