package entity

type Settings struct {
	Sn                int `json:"sn"`
	AccountId         string `json:"account_id"`
	TwofaEmail        int `json:"twofa_email"`
	TwofaPhone        int `json:"twofa_phone"`
	TwofaGoogleAuth   int `json:"twofa_google_auth"`
	LockedWallets     string `json:"locked_wallets"`
	AntiPhishingToken string `json:"anti_phishing_token"`
}
