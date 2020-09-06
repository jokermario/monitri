package entity

import "time"

// Accounts represents an account.
type Accounts struct {
	Sn                 int       `json:"sn"`
	Id                 string    `json:"id"`
	Firstname          string    `json:"firstname"`
	Middlename         string    `json:"middlename"`
	Lastname           string    `json:"lastname"`
	Dob                string    `json:"dob"`
	Email              string    `json:"email"`
	Password           string    `json:"password"`
	Address            string    `json:"address"`
	Phone              string    `json:"phone"`
	Bankname           string    `json:"bankname"`
	BankAccountNo      string    `json:"bank_account_no"`
	ConfirmedEmail     int       `json:"confirmed_email"`
	ConfirmEmailToken  int       `json:"confirm_email_token"`
	ConfirmEmailExpiry int       `json:"confirm_email_expiry"`
	ConfirmedPhone     int       `json:"confirmed_phone"`
	ConfirmPhoneToken  int       `json:"confirm_phone_token"`
	ConfirmPhoneExpiry int       `json:"confirm_phone_expiry"`
	Managed            int       `json:"managed"`
	AccountManagerId   string    `json:"account_manager_id"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
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
	return a.Bankname
}

func (a Accounts) GetBankAccountNo() string {
	return a.BankAccountNo
}