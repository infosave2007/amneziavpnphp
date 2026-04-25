# Amnezia VPN Web Panel

Веб-панель управления для VPN-серверов Amnezia AWG (WireGuard).

## Возможности

- Развертывание VPN-серверов через SSH (пароль или **SSH-ключ**)
- **Импорт из существующих VPN-панелей** (wg-easy, 3x-ui)
- **Расширенное управление протоколами** (WireGuard, AmneziaWG, OpenVPN, Shadowsocks и др.)
- **AI-настройка протоколов** через OpenRouter (опционально)
- Управление клиентскими конфигурациями с **датами истечения**
- **Лимиты трафика** для клиентов с автоматическим применением
- **Резервное копирование и восстановление** серверов
- **Тестирование сценариев**: определение и проверка различных сценариев подключения VPN across протоколов
- **Расширенное управление логами**: просмотр, поиск и управление системными и контейнерными логами
- Мониторинг статистики трафика
- Генерация QR-кодов для мобильных приложений
- Многоязычный интерфейс (английский, русский, испанский, немецкий, французский, китайский)
- REST API с JWT-аутентификацией
- Аутентификация пользователей и контроль доступа
- **Автоматическая проверка истечения срока действия клиентов и лимитов трафика** через cron

## Доступные протоколы

- AmneziaWG Advanced (`amnezia-wg-advanced`)
- AmneziaWG 2.0 (`awg2`)
- WireGuard Standard (`wireguard-standard`)
- OpenVPN (`openvpn`)
- Shadowsocks (`shadowsocks`)
- XRay VLESS (`xray-vless`)
- MTProxy (Telegram) (`mtproxy`)
- SMB Server (`smb`)
- AIVPN (`aivpn`) - https://github.com/infosave2007/aivpn
- Cloudflare WARP Proxy (`cf-warp`) — прозрачное проксирование трафика через Cloudflare

## Требования

- Docker
- Docker Compose

## Установка

```bash
git clone https://github.com/infosave2007/amneziavpnphp.git
cd amneziavpnphp
cp .env.example .env

# Для Docker Compose V2 (рекомендуется)
docker compose up -d
docker compose exec web composer install

# Дождитесь готовности БД (начальные SQL-файлы миграции применяются автоматически через MySQL entrypoint)
until [ "$(docker inspect -f '{{.State.Health.Status}}' amnezia-panel-db 2>/dev/null)" = "healthy" ]; do
  sleep 2
done

# Или для старой Docker Compose V1
docker-compose up -d
docker-compose exec web composer install

until [ "$(docker inspect -f '{{.State.Health.Status}}' amnezia-panel-db 2>/dev/null)" = "healthy" ]; do
  sleep 2
done

# Ручной режим миграции (для существующих установок / обновлений)
set -a; source .env; set +a
for f in migrations/*.sql; do
  docker compose exec -T db mysql -u"$DB_USERNAME" -p"$DB_PASSWORD" "$DB_DATABASE" < "$f" || true
done

# Для Docker Compose V1 ручной режим миграции:
# for f in migrations/*.sql; do
#   docker-compose exec -T db mysql -u"$DB_USERNAME" -p"$DB_PASSWORD" "$DB_DATABASE" < "$f" || true
# done
```

Доступ: http://localhost:8082

Данные для входа по умолчанию: admin@amnez.ia / admin123

### Предварительные требования для удаленного сервера

Для развертывания протоколов на чистом удаленном хосте, Docker Engine должен быть доступен на этом хосте.
Если Docker отсутствует, установите его сначала (пример для Ubuntu):

```bash
apt-get update -y
apt-get install -y ca-certificates curl gnupg lsb-release
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --batch --yes --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg
. /etc/os-release
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable" > /etc/apt/sources.list.d/docker.list
apt-get update -y
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable --now docker
```

## Настройка

Отредактируйте `.env`:

```
DB_HOST=db
DB_PORT=3306
DB_DATABASE=amnezia_panel
DB_USERNAME=amnezia
DB_PASSWORD=amnezia

ADMIN_EMAIL=admin@amnez.ia
ADMIN_PASSWORD=admin123

JWT_SECRET=your-secret-key-change-this
```

## Использование

### Добавление VPN-сервера

1. Серверы → Добавить сервер
2. Введите: имя, IP хоста, SSH-порт, имя пользователя
3. Выберите метод аутентификации: **Пароль** или **SSH-ключ**
   - Для SSH-ключа: вставьте ваш приватный ключ (формат PEM/OpenSSH)
3. **(Опционально) Включите импорт из существующей панели:**
   - Отметьте "Импортировать из существующей панели"
   - Выберите тип панели (wg-easy или 3x-ui)
   - Загрузите файл резервной копии (JSON)
4. Нажмите "Создать сервер"
5. Дождитесь развертывания
6. Клиенты будут импортированы автоматически, если импорт был включен

### Создание клиента

1. Откройте детали сервера
2. Введите имя клиента
3. **Выберите период истечения** (опционально, по умолчанию: бессрочно)
4. **Выберите лимит трафика** (опционально, по умолчанию: безлимитно)
5. Нажмите "Создать клиента"
6. Скачайте конфигурацию или отсканируйте QR-код

### Управление истечением срока действия клиента

Установите истечение через UI или API:
```bash
# Установить конкретную дату
curl -X POST http://localhost:8082/api/clients/123/set-expiration \
  -H "Authorization: Bearer <token>" \
  -d '{"expires_at": "2025-12-31 23:59:59"}'

# Продлить на 30 дней
curl -X POST http://localhost:8082/api/clients/123/extend \
  -H "Authorization: Bearer <token>" \
  -d '{"days": 30}'

# Получить клиентов, у которых скоро истекает срок (в течение 7 дней)
curl http://localhost:8082/api/clients/expiring?days=7 \
  -H "Authorization: Bearer <token>"
```

### Управление лимитами трафика

Установите и отслеживайте лимиты трафика через UI или API:
```bash
# Установить лимит трафика (10 ГБ = 10737418240 байт)
curl -X POST http://localhost:8082/api/clients/123/set-traffic-limit \
  -H "Authorization: Bearer <token>" \
  -d '{"limit_bytes": 10737418240}'

# Удалить лимит трафика (установить безлимитный)
curl -X POST http://localhost:8082/api/clients/123/set-traffic-limit \
  -H "Authorization: Bearer <token>" \
  -d '{"limit_bytes": null}'

# Проверить статус лимита трафика
curl http://localhost:8082/api/clients/123/traffic-limit-status \
  -H "Authorization: Bearer <token>"

# Получить клиентов, превысивших лимит трафика
curl http://localhost:8082/api/clients/overlimit \
  -H "Authorization: Bearer <token>"
```

### Резервное копирование серверов

Создавайте и восстанавливайте резервные копии через UI или API:
```bash
# Создать резервную копию
curl -X POST http://localhost:8082/api/servers/1/backup \
  -H "Authorization: Bearer <token>"

# Список резервных копий
curl http://localhost:8082/api/servers/1/backups \
  -H "Authorization: Bearer <token>"

# Восстановить из резервной копии
curl -X POST http://localhost:8082/api/servers/1/restore \
  -H "Authorization: Bearer <token>" \
  -d '{"backup_id": 123}'
```

### Управление протоколами

Управляйте VPN-протоколами через **Настройки → Протоколы**:
- Установка/удаление протоколов (WireGuard, AmneziaWG, OpenVPN и др.)
- Настройка параметров протокола (порты, транспорт, маскировка)
- **AI-ассистент**: используйте "Спросить AI" для генерации сложных конфигураций протоколов, адаптированных к вашим потребностям (требуется API-ключ OpenRouter).

### Cloudflare WARP Proxy

WARP прозрачно проксирует **весь TCP-трафик** от VPN-клиентов через сеть Cloudflare, скрывая реальный IP-адрес сервера.

> **⚠️ Устанавливайте WARP последним** — после всех других протоколов (AWG, X-Ray, AIVPN и др.). Во время установки WARP автоматически обнаруживает активные VPN-контейнеры и интерфейсы и настраивает маршрутизацию для каждого из них.

**Поддерживаемые протоколы:**
- **AWG / AWG2** — маршрутизация через IP контейнера + хост redsocks
- **X-Ray VLESS** — исходящий `warp-out` через SOCKS5 в конфигурации X-Ray
- **AIVPN / WireGuard** — маршрутизация через iptables + redsocks на уровне хоста

**Проверка:** подключитесь к VPN и откройте `https://1.1.1.1/cdn-cgi/trace` — поле `warp=on` подтверждает работоспособность.

### Тестирование сценариев и логи

**Тестирование сценариев**:
- Создавайте тестовые сценарии для проверки подключения через различные протоколы и сетевые условия.
- Запускайте автоматические тесты для обеспечения надежности вашей VPN-инфраструктуры.

**Управление логами**:
- Централизованный просмотр всех системных, контейнерных и прикладных логов.
- Возможности поиска и фильтрации для быстрой диагностики проблем.

### AI-ассистент

Настройте API-ключ OpenRouter in **Настройки** для включения:
- Автоматический перевод интерфейса
- AI-помощник для настройки протоколов
- Интеллектуальные предложения по устранению неполадок

### Автоматический мониторинг и сбор метрик

**Сборщик метрик запускается автоматически** при старте контейнера и отслеживается cron каждые 3 минуты. Если процесс падает, он автоматически перезапускается.

Проверить логи сборщика метрик:
```bash
docker compose exec web tail -f /var/log/metrics_collector.log
```

Проверить логи скрипта мониторинга:
```bash
docker compose exec web tail -f /var/log/metrics_monitor.log
```

Перезапустить сборщик метрик вручную:
```bash
docker compose exec web pkill -f collect_metrics.php
# Он будет автоматически перезапущен в течение 3 минут скриптом мониторинга
```

### Автоматическая проверка истечения срока действия клиентов

**Запускается автоматически в Docker-контейнере** каждый час для отключения истекших клиентов.

Проверить логи cron:
```bash
docker compose exec web tail -f /var/log/cron.log
```

Запустить вручную:
```bash
docker compose exec web php /var/www/html/bin/check_expired_clients.php
```

### Автоматическая проверка лимитов трафика

**Запускается автоматически в Docker-контейнере** каждый час для отключения клиентов, превысивших лимит трафика.

Проверить логи cron:
```bash
docker compose exec web tail -f /var/log/cron.log
```

Запустить вручную:
```bash
docker compose exec web php /var/www/html/bin/check_traffic_limits.php
```

### API-аутентификация

Получить JWT-токен:
```bash
curl -X POST http://localhost:8082/api/auth/token \
  -d "email=admin@amnez.ia&password=admin123"
```

Использовать токен:
```bash
curl -H "Authorization: Bearer <token>" \
  http://localhost:8082/api/servers
```

## API Endpoints

### Аутентификация
```
POST   /api/auth/token              - Получить JWT-токен
POST   /api/tokens                  - Создать постоянный API-токен
GET    /api/tokens                  - Список API-токенов
DELETE /api/tokens/{id}             - Отозвать токен
```

### Серверы
```
GET    /api/servers                 - Список всех серверов
POST   /api/servers/create          - Создать новый сервер
       Параметры: name, host, port, username, password
DELETE /api/servers/{id}/delete     - Удалить сервер по ID
GET    /api/servers/{id}/clients    - Список клиентов на сервере
```

### Протоколы
```
GET    /api/protocols/active        - Список всех доступных протоколов (JWT-дружественный, включает ID протоколов)
GET    /api/protocols               - Управление протоколами (требует session admin auth, не JWT)
GET    /api/servers/{id}/protocols  - Список установленных протоколов на сервере
POST   /api/servers/{id}/protocols/install - Установить протокол
```

### Клиенты
```
GET    /api/clients                 - Список всех клиентов
GET    /api/clients/{id}/details    - Получить детали клиента со статистикой, конфигурацией и QR-кодом
GET    /api/clients/{id}/qr         - Получить QR-код клиента
POST   /api/clients/create          - Создать нового клиента (возвращает конфигурацию и QR-код)
       Параметры: server_id, name, protocol_id (опционально, по умолчанию: установлен), expires_in_days (опционально)
POST   /api/clients/{id}/revoke     - Отозвать доступ клиента
POST   /api/clients/{id}/restore    - Восстановить доступ клиента
DELETE /api/clients/{id}/delete     - Удалить клиента по ID (удаляет из БД и сервера)
POST   /api/clients/{id}/set-expiration  - Установить дату истечения клиента
       Параметры: expires_at (Y-m-d H:i:s или null)
POST   /api/clients/{id}/extend     - Продлить истечение клиента
       Параметры: days (int)
GET    /api/clients/expiring        - Получить клиентов, у которых скоро истекает срок
       Параметры: days (по умолчанию: 7)
POST   /api/clients/{id}/set-traffic-limit  - Установить лимит трафика клиента
       Параметры: limit_bytes (int или null для безлимитного)
GET    /api/clients/{id}/traffic-limit-status - Получить статус лимита трафика
GET    /api/clients/overlimit       - Получить клиентов, превысивших лимит трафика
```

### Резервные копии
```
POST   /api/servers/{id}/backup     - Создать резервную копию сервера
GET    /api/servers/{id}/backups    - Список резервных копий сервера
POST   /api/servers/{id}/restore    - Восстановить из резервной копии
       Параметры: backup_id
DELETE /api/backups/{id}             - Удалить резервную копию
```

### Импорт панели
```
POST   /api/servers/{id}/import     - Импортировать клиентов из существующей панели
       Параметры: panel_type (wg-easy|3x-ui), backup_file (multipart/form-data)
GET    /api/servers/{id}/imports    - Получить историю импорта для сервера
```

## Перевод

Добавьте API-ключ OpenRouter в настройках, затем запустите:
```bash
docker compose exec web php bin/translate_all.php
```

Или переведите через веб-интерфейс: Настройки → Автоперевод

## Структура

```
public/index.php      - Маршруты
inc/                  - Основные классы
  Auth.php           - Аутентификация
  DB.php             - Подключение к базе данных
  Router.php         - Маршрутизация URL
  View.php           - Twig-шаблоны
  VpnServer.php      - Управление серверами
  VpnClient.php      - Управление клиентами
  Translator.php     - Многоязычность
  JWT.php            - Токен-аутентификация
  QrUtil.php         - Генерация QR-кодов
  PanelImporter.php  - Импорт из wg-easy/3x-ui
  InstallProtocolManager.php - Ядро управления протоколами
  OpenRouterService.php - AI-интеграция
templates/           - Twig-шаблоны
migrations/          - SQL-миграции (выполняются в алфавитном порядке)
```

## Технологический стек

- PHP 8.2
- MySQL 8.0
- Twig 3
- Tailwind CSS
- Docker

## Лицензия

MIT

## Поддержать проект

Если вы находите этот проект полезным, вы можете поддержать его разработку через пожертвование через Tribute: https://t.me/tribute/app?startapp=dzX1