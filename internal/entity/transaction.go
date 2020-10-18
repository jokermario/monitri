package entity

import (
	"github.com/lib/pq"
	"time"
)

type Transactions struct {
	Id                  pq.Int64Array `db:"-" json:"-"`
	AccountId           string        `json:"account_id"`
	TransactionId       string        `json:"transaction_id"`
	Amount              int64         `json:"amount"`
	TransactionHash     string        `json:"transaction_hash"`
	Status              string        `json:"status"`
	TransactionType     string        `json:"transaction_type"`
	Currency            string        `json:"currency"`
	CurrentCurrencyRate int           `json:"current_currency_rate"`
	Description         string        `json:"description"`
	CurrentBalance      int64         `json:"current_balance"`
	WalletId            string        `json:"wallet_id"`
	RecipientWalletId   string        `json:"recipient_wallet_id"`
	RecipientEmail      string        `json:"recipient_email"`
	RecipientPhone      string        `json:"recipient_phone"`
	RecipientAccNo      string        `json:"recipient_acc_no"`
	SendingWalletId     string        `json:"sending_wallet_id"`
	ReleaseDate         string        `json:"release_date"`
	CreatedAt           time.Time     `json:"created_at"`
	UpdatedAt           time.Time     `json:"updated_at"`
}
