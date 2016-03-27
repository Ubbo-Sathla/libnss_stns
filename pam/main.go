package main

/*
#include <security/pam_appl.h>
*/
import "C"
import (
	"log"

	"github.com/STNS/libnss_stns/config"
	"github.com/STNS/libnss_stns/logger"
)

//export pam_sm_authenticate
func pam_sm_authenticate(pamh *C.pam_handle_t, flags C.int, argc C.int, argv **C.char) C.int {
	logger.Setlog()
	config, err := config.Load("/etc/stns/libnss_stns.conf")
	if err != nil {
		log.Println(err)
		return C.PAM_AUTHINFO_UNAVAIL
	}

	certifier := getCertifier(pamh, argc, argv, config)
	if certifier != nil {
		user := certifier.getUser()
		if user == "" {
			return C.PAM_USER_UNKNOWN
		}
		return certifier.Auth(user)
	}

	return C.PAM_AUTH_ERR
}

//export pam_sm_setcred
func pam_sm_setcred(pamh *C.pam_handle_t, flags C.int, argc C.int, argv **C.char) C.int {
	return C.PAM_SUCCESS
}

func main() {
}
