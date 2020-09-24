package stns

import "github.com/STNS/STNS/model"

type Attributes map[string]Attribute

type Attribute struct {
	ID   int    `toml:"id" json:"id" yaml:"id" validate:"required,gte=0"`
	Name string `toml:"name" json:"name" yaml:"name"`
	*model.User
	*model.Group

	*OtpStatus
	*SmsRequest
	*VerifyStatus
}

type SmsRequest struct {
	SendStatus bool `json:"send_status"`
}

type OtpStatus struct {
	OtpEnable bool `json:"otp_enable"`
}

type VerifyStatus struct {
	Status bool `json:"status"`
}
