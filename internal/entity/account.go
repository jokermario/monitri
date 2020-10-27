package entity

import (
	"time"
)

// Accounts represents an account.
type Accounts struct {
	AccessUUID         string    `json:"-" db:"-"`
	RefreshUUID        string    `json:"-" db:"-"`
	RefreshToken       string    `json:"-" db:"-"`
	Id                 string    `json:"-"`
	Firstname          string    `json:"firstname,omitempty"`
	Middlename         string    `json:"middlename,omitempty"`
	Lastname           string    `json:"lastname,omitempty"`
	Dob                string    `json:"dob,omitempty"`
	Email              string    `json:"email,omitempty"`
	Password           string    `json:"-"`
	Address            string    `json:"address,omitempty"`
	Phone              string    `json:"phone,omitempty"`
	BankCode           string    `json:"bank_code,omitempty"`
	BankAccountNo      string    `json:"bank_account_no,omitempty"`
	RecipientCode      string    `json:"recipient_code"`
	CurrentBalance     int       `json:"current_balance"`
	ConfirmedEmail     int       `json:"confirmed_email,omitempty"`
	ConfirmEmailToken  int       `json:"confirm_email_token,omitempty"`
	ConfirmEmailExpiry int64     `json:"confirm_email_expiry,omitempty"`
	ConfirmedPhone     int       `json:"confirmed_phone,omitempty"`
	ConfirmPhoneToken  int       `json:"confirm_phone_token,omitempty"`
	ConfirmPhoneExpiry int64     `json:"confirm_phone_expiry,omitempty"`
	LoginEmailToken    int       `json:"login_email_token,omitempty"`
	LoginEmailExpiry   int64     `json:"login_email_expiry,omitempty"`
	LoginPhoneToken    int       `json:"login_phone_token,omitempty"`
	LoginPhoneExpiry   int64     `json:"login_phone_expiry,omitempty"`
	Managed            int       `json:"managed,omitempty"`
	AccountManagerId   string    `json:"account_manager_id,omitempty"`
	TotpSecret         string    `json:"-"`
	CreatedAt          time.Time `json:"created_at,omitempty"`
	UpdatedAt          time.Time `json:"updated_at,omitempty"`
}

func (a Accounts) GetAccessID() string {
	return a.AccessUUID
}

func (a Accounts) GetRefreshID() string {
	return a.RefreshUUID
}

func (a Accounts) GetTOTPSecret() string {
	return a.TotpSecret
}

func (a Accounts) GetRefreshToken() string {
	return a.RefreshToken
}

// GetID returns the accounts ID.
func (a Accounts) GetID() string {
	return a.Id
}

// GetName returns the accounts name.
func (a Accounts) GetFirstName() string {
	return a.Firstname
}

func (a Accounts) GetMiddleName() string {
	return a.Middlename
}

func (a Accounts) GetLastName() string {
	return a.Lastname
}

func (a Accounts) GetDOB() string {
	return a.Dob
}

func (a Accounts) GetEmail() string {
	return a.Email
}

func (a Accounts) GetAddress() string {
	return a.Address
}

func (a Accounts) GetPhone() string {
	return a.Phone
}

func (a Accounts) GetBankName() string {
	return a.BankCode
}

func (a Accounts) GetBankAccountNo() string {
	return a.BankAccountNo
}
