package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

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
		TimeZone: env.TimeZone,
	}
	fmt.Printf("CONFIG - %+v", postgresConfig)
	scp := postgres.NewSchemaConnectionPool(postgresConfig, log)
	authDb, err := scp.GetConnectionPool("public")
	if err != nil {
		log.Fatalf("failed connection to db: %v", err)
	}

	err = auth.RunAuthMigration(authDb)
	if err != nil {
		log.Fatalf("migration error: %v", err)
	}

	storage := auth.NewStorage(scp)

	service := auth.NewService(storage, authLog, env.JwtSecret)

	handler := auth.NewHandler(service, authLog, env.JwtSecret)

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
