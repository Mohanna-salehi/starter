package repository

import (
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/gorm"
)

const pgDuplicateErrorCode = "23505"

var ErrDuplicated = errors.New("duplicated")

type BaseRepository[T any] struct {
	db *gorm.DB
}

func (r *BaseRepository[T]) FindById(id uint) (T, error) {
	var t T
	err := r.db.First(&t, id).Error
	if err != nil {
		return t, err
	}
	return t, nil
}

func (r *BaseRepository[T]) Add(t T) error {
	err := r.db.Create(&t).Error
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgDuplicateErrorCode {
			return ErrDuplicated
		}
		return err
	}
	return nil
}

func (r *BaseRepository[T]) FindAll() ([]T, error) {
	var t []T
	err := r.db.Find(&t).Error
	if err != nil {
		return nil, err
	}
	return t, nil
}
