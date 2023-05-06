package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	_ "github.com/lib/pq"

	"github.com/gin-gonic/gin"
	"github.com/mserebryaakov/aggregator-auth-service/config"
	"github.com/mserebryaakov/aggregator-auth-service/internal/auth"
	"github.com/mserebryaakov/aggregator-auth-service/pkg/httpserver"
	"github.com/mserebryaakov/aggregator-auth-service/pkg/logger"
	"github.com/mserebryaakov/aggregator-auth-service/pkg/postgres"
)

func main() {
	log := logger.NewLogger("debug", &logger.MainLogHook{})

	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("failed to load configs: %v", err)
	}

	env, err := config.GetEnvironment()
	if err != nil {
		log.Fatalf(err.Error())
	}

	authLog := logger.NewLogger(env.LogLvl, &auth.AuthLogHook{})

	postgresConfig := postgres.Config{
		Host:     env.PgHost,
		Port:     env.PgPort,
		Username: env.PgUser,
		Password: env.PgPassword,
		DBName:   env.PgDbName,
		SSLMode:  env.SSLMode,
	}
	authPostgres, err := postgres.NewDB(postgresConfig)
	if err != nil {
		log.Fatalf("failed to connection to db: %v", err)
	}
	err = postgres.RunDBMigration(cfg.Server.MigratePath, postgresConfig)
	if err != nil {
		log.Fatalf("failed migrate: %v", err)
	}

	storage := auth.NewStorage(authPostgres)

	service := auth.NewService(storage, authLog)

	handler := auth.NewHandler(service, authLog)

	router := gin.New()

	handler.Register(router)

	server := new(httpserver.Server)

	go func() {
		if err := server.Run(cfg.Server.Port, router); err != nil {
			log.Fatal("failed running server %v", err)
		}
	}()

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)

	oscall := <-interrupt
	log.Infof("shutdown server, %s", oscall)

	if err := server.Shutdown(context.Background()); err != nil {
		log.Errorf("error occured on server shutting down: %v", err)
	}
}
