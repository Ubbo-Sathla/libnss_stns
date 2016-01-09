package libnss_stns

import (
	"fmt"
	"log"
	"reflect"

	"github.com/pyama86/libnss_stns/config"
	"github.com/pyama86/libnss_stns/logger"
)

const configFile = "/etc/stns/libnss_stns.conf"

var loaded *config.Config

func Init(name string) (*config.Config, error) {

	if reflect.ValueOf(loaded).IsNil() {
		if err := logger.Init(name); err != nil {
			fmt.Print(err)
			return nil, err
		}
		config, err := config.Load(configFile)
		if err != nil {
			log.Print(err)
			return nil, err
		}
		loaded = config
	}
	return loaded, nil
}