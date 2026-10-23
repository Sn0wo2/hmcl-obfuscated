package hmcl

import "encoding/json/jsontext"

type Account struct {
	AccountID   string         `json:"accountID"`
	PrivateData PrivateData    `json:"privateData"`
	Extra       jsontext.Value `json:",embed"`
}

type PrivateData struct {
	ProfileName  *string        `json:"profileName,omitzero"`
	TokenType    *string        `json:"tokenType,omitzero"`
	AccessToken  *string        `json:"accessToken,omitzero"`
	RefreshToken *string        `json:"refreshToken,omitzero"`
	NotAfter     *int64         `json:"notAfter,omitzero"`
	UserID       *string        `json:"userid,omitzero"`
	Extra        jsontext.Value `json:",embed"`
}
