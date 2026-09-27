package repository

import (
	"example.com/pan-vault/internal/model"
	"gorm.io/gorm"
)

type AuditRepository struct {
	*BaseRepository[model.Audit]
}

func NewAuditRepository(db *gorm.DB) *AuditRepository {
	return &AuditRepository{
		&BaseRepository[model.Audit]{
			db: db,
		},
	}
}
