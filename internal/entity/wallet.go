package entity

import (
	"time"
)

//Wallets represents a wallet info
type Wallets struct {
	ID             string    `json:"-"`
	AccountID      string    `json:"account_id"`
	WalletID       string    `json:"-"`
	WalletAddress  string    `json:"wallet_address"`
	AmountInWallet int       `json:"amount_in_wallet"`
	Currency       string    `json:"currency"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}
