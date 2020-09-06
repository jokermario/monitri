package entity

type Settings struct {
	Sn                int `json:"sn"`
	AccountId         string `json:"account_id"`
	TwoFAEmail        int `json:"twofa_email"`
	TwoFAPhone        int `json:"twofa_phone"`
	TwoFAGoogleAuth   int `json:"twofa_google_auth"`
	LockedWallets     string `json:"locked_wallets"`
	AntiPhishingToken string `json:"anti_phishing_token"`
}
