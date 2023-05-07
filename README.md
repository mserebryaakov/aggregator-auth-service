## aggregator-aurg-service - golang сервис для работы с пользователями/авторизацией/аутентификацией

### Краткое описание:

- Gin
- Docker (docker-compose)

### Применены следующие пакеты:

- gin - http framework
- viper - конфигурация
- logrus - логирование
- godotenv - переменные окружения

### Docker

    docker build . -t auth-service:latest

    docker run --env-file ./.env -p 8080:8080 auth-service:latest