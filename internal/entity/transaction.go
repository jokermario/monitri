package entity

import (
	"time"
)

//Transactions represents a transaction info
type Transactions struct {
	ID                  string    `json:"-"`
	AccountID           string    `json:"account_id"`
	TransactionID       string    `json:"transaction_id"`
	Amount              int       `json:"amount"`
	TransactionHash     string    `json:"transaction_hash"`
	Status              string    `json:"status"`
	TransactionType     string    `json:"transaction_type"`
	Currency            string    `json:"currency"`
	CurrentCurrencyRate int       `json:"current_currency_rate"`
	Description         string    `json:"description"`
	WalletID            string    `json:"wallet_id"`
	RecipientWalletID   string    `json:"recipient_wallet_id"`
	RecipientEmail      string    `json:"recipient_email"`
	RecipientPhone      string    `json:"recipient_phone"`
	RecipientAccNo      string    `json:"recipient_acc_no"`
	SendingWalletID     string    `json:"sending_wallet_id"`
	ReleaseDate         string    `json:"release_date"`
	PaystackPayload     string    `json:"-"`
	CreatedAt           time.Time `json:"created_at,omitempty"`
	UpdatedAt           time.Time `json:"updated_at,omitempty"`
}
