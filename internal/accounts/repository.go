package accounts

import (
	"context"
	dbx "github.com/go-ozzo/ozzo-dbx"
	"github.com/gomodule/redigo/redis"
	"github.com/jokermario/monitri/internal/entity"
	"github.com/jokermario/monitri/pkg/dbcontext"
	"github.com/jokermario/monitri/pkg/log"
)

//Repository is an interface to the repository
type Repository interface {
	GetAccountByID(ctx context.Context, id string) (entity.Accounts, error)
	GetAccountIDEmailPhone(ctx context.Context, id string) (entity.Accounts, error)
	GetAccountByEmail(ctx context.Context, email string) (entity.Accounts, error)
	GetAccountByPhone(ctx context.Context, phone string) (entity.Accounts, error)
	AccountCreate(ctx context.Context, account entity.Accounts) error
	AccountCount(ctx context.Context) (int, error)
	AccountUpdate(ctx context.Context, accounts entity.Accounts) error
	AccountDelete(ctx context.Context, id string) error
	GetAccounts(ctx context.Context, offset, limit int) ([]entity.Accounts, error)
	SetRedisKey(conn redis.Conn, exp int64, key, value string) error
	GetRedisKey(conn redis.Conn, key string) (string, error)
	DeleteRedisKeys(conn redis.Conn, keys ...string) error
	updateAccountAndSettingsTableTrans(ctx context.Context, accounts entity.Accounts, settings entity.Settings, Type string) error
	GetSettingsByID(ctx context.Context, id string) (entity.Settings, error)
	CreateSettings(ctx context.Context, settings entity.Settings) error
	UpdateSettings(ctx context.Context, settings entity.Settings) error
	DeleteSettings(ctx context.Context, id string) error
	TransactionCreate(ctx context.Context, transaction entity.Transactions) error
	WalletCreate(ctx context.Context, wallet entity.Wallets) error
	GetTransactionByTransRef(ctx context.Context, transRef string) (entity.Transactions, error)
	TransactionUpdate(ctx context.Context, transaction entity.Transactions) error
	//GetLatestTransaction(ctx context.Context, accountId string) (entity.Transactions, error)
	updateAccountAndTransactionTableTrans(ctx context.Context, accounts entity.Accounts, transactions entity.Transactions) error
	updateTwoAccountAndTransactionTableTrans(ctx context.Context, accounts entity.Accounts,
		accounts2 entity.Accounts, transactions entity.Transactions, transactions2 entity.Transactions) error
}

type repository struct {
	db     *dbcontext.DB
	logger log.Logger
}

//NewRepository returns an instance of the repository struct
func NewRepository(db *dbcontext.DB, logger log.Logger) Repository {
	return &repository{db, logger}
}

//------------------------------------------------------ACCOUNTS--------------------------------------------------------

func (r *repository) GetAccountByID(ctx context.Context, id string) (entity.Accounts, error) {

	var account entity.Accounts
	err := r.db.With(ctx).Select().Model(id, &account)
	return account, err
}

func (r *repository) GetAccountIDEmailPhone(ctx context.Context, id string) (entity.Accounts, error) {

	var account entity.Accounts
	err := r.db.
		With(ctx).
		Select("id", "email", "phone").
		From("accounts").
		Where(dbx.NewExp("id={:id}", dbx.Params{"id": id})).One(&account)
	return account, err
}

func (r *repository) GetAccountByEmail(ctx context.Context, email string) (entity.Accounts, error) {

	var account entity.Accounts
	err := r.db.
		With(ctx).
		Select().
		From("accounts").
		Where(dbx.NewExp("email={:email}", dbx.Params{"email": email})).One(&account)
	return account, err
}

func (r *repository) GetAccountByPhone(ctx context.Context, phone string) (entity.Accounts, error) {

	var account entity.Accounts
	err := r.db.
		With(ctx).
		Select().
		From("accounts").
		Where(dbx.NewExp("phone={:phone}", dbx.Params{"phone": phone})).One(&account)
	return account, err
}

func (r *repository) AccountCreate(ctx context.Context, account entity.Accounts) error {

	return r.db.With(ctx).Model(&account).Insert()
}

func (r *repository) AccountCount(ctx context.Context) (int, error) {

	var count int
	err := r.db.With(ctx).Select("COUNT(*)").From("accounts").Row(&count)
	return count, err
}

func (r *repository) AccountUpdate(ctx context.Context, accounts entity.Accounts) error {

	return r.db.With(ctx).Model(&accounts).Update()
}

func (r *repository) AccountDelete(ctx context.Context, id string) error {

	account, err := r.GetAccountByID(ctx, id)
	if err != nil {
		return err
	}
	return r.db.With(ctx).Model(&account).Delete()
}

func (r *repository) GetAccounts(ctx context.Context, offset, limit int) ([]entity.Accounts, error) {

	var accounts []entity.Accounts
	err := r.db.With(ctx).Select().OrderBy("id").Offset(int64(offset)).Limit(int64(limit)).All(&accounts)
	return accounts, err
}

//-----------------------------------------------------TRANSACTIONS-----------------------------------------------------

func (r *repository) GetTransactionByTransRef(ctx context.Context, transRef string) (entity.Transactions, error) {

	var transaction entity.Transactions
	err := r.db.
		With(ctx).
		Select().
		From("transactions").
		Where(dbx.NewExp("transaction_id={:trans_ref}", dbx.Params{"trans_ref": transRef})).One(&transaction)
	return transaction, err
}

func (r *repository) TransactionCreate(ctx context.Context, transaction entity.Transactions) error {

	return r.db.With(ctx).Model(&transaction).Insert()
}

func (r *repository) TransactionUpdate(ctx context.Context, transaction entity.Transactions) error {

	return r.db.With(ctx).Model(&transaction).Update()
}

//func (r repository) GetLatestTransaction(ctx context.Context, accountId string) (entity.Transactions, error) {
//	var transaction entity.Transactions
//	err := r.db.
//		With(ctx).
//		Select().
//		From("transactions").
//		OrderBy("created_at DESC").
//		Where(dbx.NewExp("account_id={:account_id}", dbx.Params{"account_id":accountId})).
//		AndWhere(dbx.NewExp("current_balance>{:zero_val}", dbx.Params{"zero_val":0})).One(&transaction)
//	return transaction, err
//}

//-------------------------------------------------------WALLETS--------------------------------------------------------

func (r *repository) WalletCreate(ctx context.Context, wallet entity.Wallets) error {

	return r.db.With(ctx).Model(&wallet).Insert()
}

//------------------------------------------------------SETTINGS--------------------------------------------------------

func (r *repository) GetSettingsByID(ctx context.Context, id string) (entity.Settings, error) {

	var settings entity.Settings
	err := r.db.
		With(ctx).
		Select().
		From("settings").
		Where(dbx.NewExp("account_id={:id}", dbx.Params{"id": id})).One(&settings)
	return settings, err
}

func (r *repository) CreateSettings(ctx context.Context, settings entity.Settings) error {

	return r.db.With(ctx).Model(&settings).Insert()
}

func (r *repository) UpdateSettings(ctx context.Context, settings entity.Settings) error {

	return r.db.With(ctx).Model(&settings).Update()
}

func (r *repository) DeleteSettings(ctx context.Context, id string) error {

	settings, err := r.GetSettingsByID(ctx, id)
	if err != nil {
		return err
	}
	return r.db.With(ctx).Model(&settings).Delete()
}

//-----------------------------------------------------TRANSACTIONAL----------------------------------------------------

func (r *repository) updateAccountAndSettingsTableTrans(ctx context.Context, accounts entity.Accounts,
	settings entity.Settings, Type string) error {

	if err := r.db.Transactional(ctx, func(ctx context.Context) error {
		if Type == "insert" {
			if accUpdateErr := r.db.With(ctx).Model(&accounts).Update(); accUpdateErr != nil {
				return accUpdateErr
			}
			if setUpdateErr := r.db.With(ctx).Model(&settings).Insert(); setUpdateErr != nil {
				return setUpdateErr
			}
		}

		if Type == "update" {
			if accUpdateErr := r.db.With(ctx).Model(&accounts).Update(); accUpdateErr != nil {
				return accUpdateErr
			}
			if setUpdateErr := r.db.With(ctx).Model(&settings).Update(); setUpdateErr != nil {
				return setUpdateErr
			}
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}

func (r *repository) updateAccountAndTransactionTableTrans(ctx context.Context, accounts entity.Accounts,
	transactions entity.Transactions) error {

	if err := r.db.Transactional(ctx, func(ctx context.Context) error {
		if accUpdateErr := r.db.With(ctx).Model(&accounts).Update(); accUpdateErr != nil {
			return accUpdateErr
		}
		if transUpdateErr := r.db.With(ctx).Model(&transactions).Update(); transUpdateErr != nil {
			return transUpdateErr
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}

func (r *repository) updateTwoAccountAndTransactionTableTrans(ctx context.Context, accounts entity.Accounts,
	accounts2 entity.Accounts, transactions entity.Transactions, transactions2 entity.Transactions) error {

	if err := r.db.Transactional(ctx, func(ctx context.Context) error {
		if accUpdateErr := r.db.With(ctx).Model(&accounts).Update(); accUpdateErr != nil {
			return accUpdateErr
		}
		if accUpdate2Err := r.db.With(ctx).Model(&accounts2).Update(); accUpdate2Err != nil {
			return accUpdate2Err
		}
		if transUpdateErr := r.db.With(ctx).Model(&transactions).Insert(); transUpdateErr != nil {
			return transUpdateErr
		}
		if transUpdate2Err := r.db.With(ctx).Model(&transactions2).Insert(); transUpdate2Err != nil {
			return transUpdate2Err
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}

//-------------------------------------------------------REDIS----------------------------------------------------------
func (r *repository) SetRedisKey(conn redis.Conn, exp int64, key, value string) error {

	_, err := conn.Do("SETEX", key, exp, value)
	if err != nil {
		return err
	}
	return nil
}

func (r *repository) GetRedisKey(conn redis.Conn, key string) (string, error) {

	s, err := redis.String(conn.Do("GET", key))
	return s, err
}

func (r *repository) DeleteRedisKeys(conn redis.Conn, keys ...string) error {

	for _, v := range keys {
		_, _ = redis.String(conn.Do("DEL", v))
	}
	return nil
}
