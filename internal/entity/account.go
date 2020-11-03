package entity

import (
	"time"
)

// Accounts represents an account info
type Accounts struct {
	AccessUUID         string    `json:"-" db:"-"`
	RefreshUUID        string    `json:"-" db:"-"`
	RefreshToken       string    `json:"-" db:"-"`
	ID                 string    `json:"-"`
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
	BankName           string    `json:"bank_name,omitempty"`
	RecipientCode      string    `json:"recipient_code"`
	CurrentBalance     int       `json:"current_balance"`
	NOKFullname        string    `json:"nok_fullname,omitempty"`
	NOKPhone           string    `json:"nok_phone,omitempty"`
	NOKEmail           string    `json:"nok_email,omitempty"`
	NOKAddress         string    `json:"nok_address,omitempty"`
	ConfirmedEmail     int       `json:"confirmed_email,omitempty"`
	ConfirmEmailToken  int       `json:"-"`
	ConfirmEmailExpiry int64     `json:"-"`
	ConfirmedPhone     int       `json:"confirmed_phone,omitempty"`
	ConfirmPhoneToken  int       `json:"-"`
	ConfirmPhoneExpiry int64     `json:"-"`
	LoginEmailToken    int       `json:"-"`
	LoginEmailExpiry   int64     `json:"-"`
	LoginPhoneToken    int       `json:"-"`
	LoginPhoneExpiry   int64     `json:"-"`
	Managed            int       `json:"managed,omitempty"`
	AccountManagerID   string    `json:"account_manager_id,omitempty"`
	TotpSecret         string    `json:"-"`
	CreatedAt          time.Time `json:"created_at,omitempty"`
	UpdatedAt          time.Time `json:"updated_at,omitempty"`
}

//GetAccessID returns the accounts current accessID
func (a Accounts) GetAccessID() string {
	return a.AccessUUID
}

//GetRefreshID returns the accounts current refreshID
func (a Accounts) GetRefreshID() string {
	return a.RefreshUUID
}

//GetTOTPSecret returns the accounts TOTPSecret
func (a Accounts) GetTOTPSecret() string {
	return a.TotpSecret
}

// GetRefreshToken returns the accounts name.
func (a Accounts) GetRefreshToken() string {
	return a.RefreshToken
}

// GetID returns the accounts ID.
func (a Accounts) GetID() string {
	return a.ID
}

// GetFirstName returns the accounts firstname.
func (a Accounts) GetFirstName() string {
	return a.Firstname
}

// GetMiddleName returns the accounts middlename.
func (a Accounts) GetMiddleName() string {
	return a.Middlename
}

// GetLastName returns the accounts lastname.
func (a Accounts) GetLastName() string {
	return a.Lastname
}

// GetDOB returns the accounts dob.
func (a Accounts) GetDOB() string {
	return a.Dob
}

// GetEmail returns the accounts email.
func (a Accounts) GetEmail() string {
	return a.Email
}

// GetAddress returns the accounts address.
func (a Accounts) GetAddress() string {
	return a.Address
}

// GetPhone returns the accounts phone.
func (a Accounts) GetPhone() string {
	return a.Phone
}

// GetBankName returns the accounts bankName.
func (a Accounts) GetBankName() string {
	return a.BankCode
}

// GetBankAccountNo returns the accounts bankAcctNo.
func (a Accounts) GetBankAccountNo() string {
	return a.BankAccountNo
}
