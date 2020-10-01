package entity

import (
	"github.com/lib/pq"
)

type Settings struct {
	Id                pq.Int64Array `db:"-" json:"-"`
	AccountId         string        `json:"account_id"`
	TwofaEmail        int           `json:"twofa_email"`
	TwofaPhone        int           `json:"twofa_phone"`
	TwofaGoogleAuth   int           `json:"twofa_google_auth"`
	LockedWallets     string        `json:"locked_wallets"`
	AntiPhishingToken string        `json:"anti_phishing_token"`
}
