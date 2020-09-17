package accounts

import (
	"context"
	dbx "github.com/go-ozzo/ozzo-dbx"
	"github.com/gomodule/redigo/redis"
	"github.com/jokermario/monitri/internal/entity"
	"github.com/jokermario/monitri/pkg/dbcontext"
	"github.com/jokermario/monitri/pkg/log"
)

type Repository interface {
	GetById(ctx context.Context, id string) (entity.Accounts, error)
	Create(ctx context.Context, account entity.Accounts) error
	Count(ctx context.Context) (int, error)
	Update(ctx context.Context, accounts entity.Accounts) error
	Delete(ctx context.Context, id string) error
	GetAccounts(ctx context.Context, offset, limit int) ([]entity.Accounts, error)
	GetIdEmailPhone(ctx context.Context, id string) (entity.Accounts, error)
	GetAccountByEmail(ctx context.Context, email string) (entity.Accounts, error)
	SetRedisKey(conn redis.Conn, exp int64, key, value string) error
	GetRedisKey(conn redis.Conn, key string) (string, error)
	DeleteRedisKeys(conn redis.Conn, keys ...string) error
}

type repository struct {
	db *dbcontext.DB
	logger log.Logger
}

func NewRepository(db *dbcontext.DB, logger log.Logger) Repository {
	return repository{db, logger}
}

func (r repository) GetById(ctx context.Context, id string) (entity.Accounts, error) {
	var account entity.Accounts
	err := r.db.With(ctx).Select().Model(id, &account)
	return account, err
}

func (r repository) GetIdEmailPhone(ctx context.Context, id string) (entity.Accounts, error) {
	var account entity.Accounts
	err := r.db.With(ctx).Select("id", "email", "phone").From("accounts").Where(dbx.NewExp("id={:id}", dbx.Params{"id":id})).One(&account)
	return account, err
}

func (r repository) GetAccountByEmail(ctx context.Context, email string) (entity.Accounts, error) {
	var account entity.Accounts
	err := r.db.With(ctx).Select().From("accounts").Where(dbx.NewExp("email={:email}", dbx.Params{"email":email})).One(&account)
	return account, err
}

func (r repository) Create(ctx context.Context, account entity.Accounts) error {
	return r.db.With(ctx).Model(&account).Insert()
}

func (r repository) Count(ctx context.Context) (int, error) {
	var count int
	err := r.db.With(ctx).Select("COUNT(*)").From("accounts").Row(&count)
	return count, err
}

func (r repository) Update(ctx context.Context, accounts entity.Accounts) error {
	return r.db.With(ctx).Model(&accounts).Update()
}

func (r repository) Delete(ctx context.Context, id string) error {
	account, err := r.GetById(ctx, id)
	if err != nil {
		return err
	}
	return r.db.With(ctx).Model(&account).Delete()
}

func (r repository) GetAccounts(ctx context.Context, offset, limit int) ([]entity.Accounts, error){
	var accounts []entity.Accounts
	err := r.db.With(ctx).Select().OrderBy("id").Offset(int64(offset)).Limit(int64(limit)).All(&accounts)
	return accounts, err
}

//redis
func (r repository) SetRedisKey(conn redis.Conn, exp int64, key, value string) error {
	_, err := conn.Do("SETEX", key, exp, value)
	if err != nil {
		return err
	}
	return nil
}

func (r repository) GetRedisKey(conn redis.Conn, key string) (string, error) {
	s, err := redis.String(conn.Do("GET", key))
	return s, err
}

func (r repository) DeleteRedisKeys(conn redis.Conn, keys ...string) error {
	for _, v := range keys {
		_, _ = redis.String(conn.Do("DEL", v))
	}
	return nil
}


