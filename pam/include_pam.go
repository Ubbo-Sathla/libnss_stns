package main

/*
#include <stdlib.h>
#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#cgo LDFLAGS: -lpam
*/
import "C"

//func disablePtrace() bool {
//	return C.disable_ptrace() == C.int(0)
//}

// The reason that separates this method, but in order to avoid a compile error

func getUserName(pamh *C.pam_handle_t, user **C.char) bool {
	if C.pam_get_user(pamh, user, nil) != C.PAM_SUCCESS {
		return false
	}
	return true
}

func getPassword(pamh *C.pam_handle_t, password **C.char) bool {
	if C.pam_get_authtok(pamh, C.PAM_AUTHTOK, password, nil) != C.PAM_SUCCESS {
		return false
	}
	return true
}
