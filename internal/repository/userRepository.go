package repository

import (
	"example.com/pan-vault/internal/model"
	"gorm.io/gorm"
)

type UserRepository struct {
	*BaseRepository[model.User]
}

func NewUserRepository(db *gorm.DB) *UserRepository {
	return &UserRepository{
		&BaseRepository[model.User]{
			db: db,
		},
	}
}

func (r *UserRepository) FindByUsername(username string) (model.User, error) {
	var user model.User

	found := r.db.Where("username = ?", username).First(&user)
	if found.Error != nil {
		return user, found.Error
	}
	return user, nil
}
