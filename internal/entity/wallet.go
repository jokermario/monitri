package entity

import "time"

type Wallets struct {
	Sn               int    `json:"sn"`
	Account_id       string `json:"account_id"`
	Wallet_id        string `json:"wallet_id"`
	Amount_in_wallet int    `json:"amount_in_wallet"`
	Currency         string `json:"currency"`
	Created_at         time.Time `json:"created_at"`
	Updated_at         time.Time `json:"updated_at"`
}
