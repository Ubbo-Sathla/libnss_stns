package internal

import (
	gsyslog "github.com/hashicorp/go-syslog"
	"github.com/op/go-logging"
	"log"
)

var logger = logging.MustGetLogger("libstns")

func InitLogger(debug bool) {
	writer, err := gsyslog.NewLogger(gsyslog.LOG_INFO, "LOCAL7", "libstns")
	if err != nil {
		log.Panic(err)
	}
	format := logging.MustStringFormatter(
		`@%{shortfile} %{message}`,
	)
	logging.SetFormatter(format)
	logging.SetBackend(logging.NewLogBackend(writer, "", 0))

	if debug {
		logging.SetLevel(logging.DEBUG, "stns")
	} else {
		logging.SetLevel(logging.INFO, "stns")
	}
}

func GetLogger() *logging.Logger {
	return logger
}
