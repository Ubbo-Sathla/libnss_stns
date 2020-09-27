package bcrypt_crypt

import (
	"github.com/tredoe/osutil/user/crypt"
	"github.com/tredoe/osutil/user/crypt/common"
	"github.com/tredoe/osutil/user/crypt/md5_crypt"
	"golang.org/x/crypto/bcrypt"
)

//func init() {
//	crypt.RegisterCrypt(crypt.BCRYPT, New, MagicPrefix)
//}

const (
	MagicPrefix   = "$2a$"
	SaltLenMin    = 1
	SaltLenMax    = 8
	RoundsDefault = 1000
)

var md5Crypt = md5_crypt.New()

func init() {
	md5Crypt.SetSalt(GetSalt())
}

type crypter struct{ Salt common.Salt }

// New returns a new crypt.Crypter computing the variant "bcrpyt" of MD5-crypt
func New() crypt.Crypter { return &crypter{common.Salt{}} }

func (c *crypter) Generate(key, salt []byte) (string, error) {
	return md5Crypt.Generate(key, salt)
}

func (c *crypter) Verify(hashedKey string, key []byte) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedKey), key)
}

func (c *crypter) Cost(hashedKey string) (int, error) { return RoundsDefault, nil }

func (c *crypter) SetSalt(salt common.Salt) {}

func GetSalt() common.Salt {
	return common.Salt{
		MagicPrefix:   []byte(MagicPrefix),
		SaltLenMin:    SaltLenMin,
		SaltLenMax:    SaltLenMax,
		RoundsDefault: RoundsDefault,
	}
}
