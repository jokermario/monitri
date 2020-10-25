package entity

import (
	"time"
)

type Wallets struct {
	Id               string    `json:"-"`
	Account_id       string    `json:"account_id"`
	Wallet_id        string    `json:"-"`
	Wallet_address   string    `json:"wallet_address"`
	Amount_in_wallet int       `json:"amount_in_wallet"`
	Currency         string    `json:"currency"`
	Created_at       time.Time `json:"created_at"`
	Updated_at       time.Time `json:"updated_at"`
}
