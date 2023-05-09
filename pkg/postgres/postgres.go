package postgres

import (
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type Config struct {
	Host     string
	Port     string
	Username string
	Password string
	DBName   string
	SSLMode  string
	TimeZone string
}

// func ConnectionToDb(cfg Config) (*gorm.DB, error) {
// 	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=%s TimeZone=%s",
// 		cfg.Host, cfg.Username, cfg.Password, cfg.DBName, cfg.Port, cfg.SSLMode, cfg.TimeZone)
// 	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})

// 	if err != nil {
// 		return nil, err
// 	}

// 	return db, nil
// }

type SchemaConnectionPool struct {
	sync.Mutex
	pools              map[string]*gorm.DB
	dbConnectionString string
	log                *logrus.Entry
}

func NewSchemaConnectionPool(cfg Config, log *logrus.Entry) *SchemaConnectionPool {
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=%s TimeZone=%s",
		cfg.Host, cfg.Username, cfg.Password, cfg.DBName, cfg.Port, cfg.SSLMode, cfg.TimeZone)
	return &SchemaConnectionPool{
		dbConnectionString: dsn,
		log:                log,
		pools:              make(map[string]*gorm.DB),
	}
}

func (scp *SchemaConnectionPool) GetConnectionPool(schemaName string) (*gorm.DB, error) {
	scp.Lock()
	defer scp.Unlock()

	if pool, ok := scp.pools[schemaName]; ok {
		return pool, nil
	}

	db, err := gorm.Open(postgres.Open(scp.dbConnectionString), &gorm.Config{
		PrepareStmt: true,
	})
	if err != nil {
		return nil, err
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}

	sqlDB.SetMaxIdleConns(1)
	sqlDB.SetMaxOpenConns(100)
	sqlDB.SetConnMaxLifetime(time.Hour)

	var count int64
	db.Raw("SELECT COUNT(*) FROM pg_namespace WHERE nspname = ?", schemaName).Scan(&count)
	if count == 0 {
		return nil, fmt.Errorf("schema not found: %s", schemaName)
	}

	err = db.Exec("SET search_path TO " + schemaName).Error
	if err != nil {
		return nil, err
	}

	scp.pools[schemaName] = db

	go func() {
		ticker := time.NewTicker(time.Second * 10)
		defer ticker.Stop()

		for range ticker.C {
			if err := sqlDB.Ping(); err != nil {
				db, err := gorm.Open(postgres.Open(scp.dbConnectionString), &gorm.Config{
					PrepareStmt: true,
				})
				if err != nil {
					continue
				}

				sqlDB, err = db.DB()
				if err != nil {
					continue
				}

				sqlDB.SetMaxIdleConns(1)
				sqlDB.SetMaxOpenConns(100)
				sqlDB.SetConnMaxLifetime(time.Hour)

				err = db.Exec("SET search_path TO " + schemaName).Error
				if err != nil {
					continue
				}

				scp.log.Infof("succes ping %s pool", schemaName)
			}
		}
	}()

	return db, nil
}
