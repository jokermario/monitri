package entity

type Settings struct {
	Id                string `json:"-"`
	AccountId         string `json:"account_id"`
	TwofaEmail        int    `json:"twofa_email"`
	TwofaGoogleAuth   int    `json:"twofa_google_auth"`
	LockedWallets     string `json:"locked_wallets"`
	AntiPhishingToken string `json:"anti_phishing_token"`
}
