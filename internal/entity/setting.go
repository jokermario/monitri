package entity

//Settings represents setings info
type Settings struct {
	ID                string `json:"-"`
	AccountID         string `json:"account_id"`
	TwofaEmail        int    `json:"twofa_email"`
	TwofaGoogleAuth   int    `json:"twofa_google_auth"`
	LockedWallets     string `json:"locked_wallets"`
	AntiPhishingToken string `json:"anti_phishing_token"`
}
