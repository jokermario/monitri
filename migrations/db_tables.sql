DROP TABLE IF EXISTS transactions;
DROP TABLE IF EXISTS wallets;
DROP TABLE IF EXISTS settings;
DROP TABLE IF EXISTS accounts;
CREATE TABLE IF NOT EXISTS accounts
                            (
                                sn SERIAL,
                                id VARCHAR(50) UNIQUE NOT NULL,
                                firstname VARCHAR(50) NULL,
                                middlename VARCHAR(50) NULL,
                                lastname VARCHAR(50) NULL,
                                dob VARCHAR(10) NULL,
                                email VARCHAR(100) UNIQUE NOT NULL,
                                password VARCHAR(100) NOT NULL,
                                address TEXT NULL,
                                phone VARCHAR(20) UNIQUE NOT NULL,
                                bankname VARCHAR(50) NULL,
                                bank_account_no VARCHAR(20) NULL,
                                confirmed_email INTEGER NOT NULL DEFAULT 0,
                                confirm_email_token INTEGER NULL,
                                confirm_email_expiry INTEGER NULL,
                                confirmed_phone INTEGER NOT NULL DEFAULT 0,
                                confirm_phone_token INTEGER NULL,
                                confirm_phone_expiry INTEGER NULL,
                                managed INTEGER NOT NULL DEFAULT 0,
                                account_manager_id VARCHAR(50) NULL,
                                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                            );
CREATE TABLE IF NOT EXISTS transactions
                            (
                                sn SERIAL,
                                account_id VARCHAR(50) NOT NULL,
                                transaction_id VARCHAR(200) NOT NULL,
                                amount INTEGER NOT NULL,
                                transaction_hash VARCHAR(200) NOT NULL,
                                status VARCHAR(50) NOT NULL,
                                transaction_type INTEGER NOT NULL,
                                current_currency_rate INTEGER NULL,
                                description TEXT NOT NULL,
                                current_balance INTEGER NOT NULL,
                                wallet_id VARCHAR(300) NOT NULL,
                                recipient_wallet_id VARCHAR(300) NULL,
                                recipient_email VARCHAR(100) NULL,
                                recipient_phone VARCHAR(20) NULL,
                                recipient_accno VARCHAR(10) NULL,
                                sending_wallet_id VARCHAR(300) NULL,
                                release_date TIMESTAMP NULL,
                                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                            );
CREATE TABLE IF NOT EXISTS wallets
                            (
                                sn SERIAL,
                                account_id VARCHAR(50) NOT NULL,
                                wallet_id VARCHAR(300) NOT NULL,
                                amount_in_wallet INTEGER NOT NULL,
                                currency INTEGER NOT NULL
                            );
CREATE TABLE IF NOT EXISTS settings
                            (
                                sn SERIAL,
                                account_id VARCHAR(50) NOT NULL,
                                twoFA_email INTEGER NOT NULL DEFAULT 0,
                                twoFA_phone INTEGER NOT NULL DEFAULT 0,
                                twoFA_google_auth INTEGER NOT NULL DEFAULT 0,
                                locked_wallets TEXT NULL,
                                anti_phishing_token VARCHAR(50) NULL
                            );

ALTER TABLE transactions ADD CONSTRAINT fk_trans_accounts FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE;
ALTER TABLE wallets ADD CONSTRAINT fk_wallet_accounts FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE;
ALTER TABLE settings ADD CONSTRAINT fk_settings_accounts FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE;