#!/bin/bash

# Amnezia VPN Panel - Auto Update Script
# Version: 2.0
# Usage: ./update.sh [--force] [--skip-backup] [--rollback]

set -e  # Exit on error
set -u  # Exit on undefined variable
set -o pipefail  # Exit on pipe failure

echo "=========================================="
echo "  Amnezia VPN Panel - Auto Update v2.0"
echo "=========================================="
echo ""

START_TIME=$(date)

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Parse arguments
FORCE_UPDATE=0
SKIP_BACKUP=0
ROLLBACK_MODE=0
ROLLBACK_VERSION=""

for arg in "$@"; do
    case $arg in
        --force) FORCE_UPDATE=1 ;;
        --skip-backup) SKIP_BACKUP=1 ;;
        --rollback) ROLLBACK_MODE=1 ;;
        --rollback=*) 
            ROLLBACK_MODE=1
            ROLLBACK_VERSION="${arg#*=}"
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --force              Force update even if already up to date"
            echo "  --skip-backup        Skip database backup (not recommended)"
            echo "  --rollback           Rollback to previous backup (interactive)"
            echo "  --rollback=TIMESTAMP Rollback to specific backup (e.g., 20251110_120000)"
            echo "  --help               Show this help message"
            echo ""
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $arg${NC}"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Log file
LOG_DIR="logs"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/update_$(date +%Y%m%d_%H%M%S).log"
BACKUP_DIR="backups"

# Logging function
log() {
    echo -e "$1" | tee -a "$LOG_FILE"
}

log_error() {
    log "${RED}✗ ERROR: $1${NC}"
}

log_success() {
    log "${GREEN}✓ $1${NC}"
}

log_warning() {
    log "${YELLOW}⚠ WARNING: $1${NC}"
}

log_info() {
    log "${BLUE}ℹ $1${NC}"
}

# Error handler
error_exit() {
    log_error "$1"
    log_info "Check log file: $LOG_FILE"
    exit 1
}

# Trap errors
trap 'error_exit "Script failed at line $LINENO"' ERR

log_info "Update started at $START_TIME"
log_info "Log file: $LOG_FILE"

# ==========================================
# ROLLBACK MODE
# ==========================================
if [ $ROLLBACK_MODE -eq 1 ]; then
    log ""
    log "${YELLOW}=========================================="
    log "  ROLLBACK MODE"
    log "==========================================${NC}"
    log ""
    
    BACKUP_DIR="backups"
    
    # Check if backups directory exists
    if [ ! -d "$BACKUP_DIR" ]; then
        error_exit "Backups directory not found: $BACKUP_DIR"
    fi
    
    # List available backups
    DB_BACKUPS=$(ls -t "$BACKUP_DIR"/db_backup_*.sql 2>/dev/null || echo "")
    
    if [ -z "$DB_BACKUPS" ]; then
        error_exit "No backups found in $BACKUP_DIR"
    fi
    
    log_info "Available backups:"
    echo ""
    
    # Create array of backups
    BACKUP_LIST=()
    INDEX=1
    for backup in $DB_BACKUPS; do
        BACKUP_FILE=$(basename "$backup")
        TIMESTAMP_EXTRACTED=$(echo "$BACKUP_FILE" | grep -o '[0-9]\{8\}_[0-9]\{6\}')
        BACKUP_DATE=$(echo "$TIMESTAMP_EXTRACTED" | sed 's/_/ /' | sed 's/\([0-9]\{4\}\)\([0-9]\{2\}\)\([0-9]\{2\}\) \([0-9]\{2\}\)\([0-9]\{2\}\)\([0-9]\{2\}\)/\1-\2-\3 \4:\5:\6/')
        BACKUP_SIZE=$(du -h "$backup" | cut -f1)
        
        echo "  [$INDEX] $BACKUP_DATE ($BACKUP_SIZE)"
        BACKUP_LIST+=("$TIMESTAMP_EXTRACTED")
        INDEX=$((INDEX + 1))
    done
    
    echo ""
    
    # Select backup
    if [ -n "$ROLLBACK_VERSION" ]; then
        # Use specified version
        SELECTED_TIMESTAMP="$ROLLBACK_VERSION"
        log_info "Using specified backup: $SELECTED_TIMESTAMP"
    else
        # Interactive selection
        echo -n "Select backup number to rollback (1-$((INDEX-1))) or 'q' to quit: "
        read -r SELECTION
        
        if [ "$SELECTION" = "q" ] || [ "$SELECTION" = "Q" ]; then
            log_info "Rollback cancelled by user"
            exit 0
        fi
        
        if ! [[ "$SELECTION" =~ ^[0-9]+$ ]] || [ "$SELECTION" -lt 1 ] || [ "$SELECTION" -ge $INDEX ]; then
            error_exit "Invalid selection: $SELECTION"
        fi
        
        SELECTED_TIMESTAMP="${BACKUP_LIST[$((SELECTION-1))]}"
    fi
    
    # Verify backup files exist
    DB_BACKUP_FILE="$BACKUP_DIR/db_backup_${SELECTED_TIMESTAMP}.sql"
    COMMIT_BACKUP_FILE="$BACKUP_DIR/commit_backup_${SELECTED_TIMESTAMP}.txt"
    ENV_BACKUP_FILE="$BACKUP_DIR/.env_backup_${SELECTED_TIMESTAMP}"
    
    if [ ! -f "$DB_BACKUP_FILE" ]; then
        error_exit "Database backup not found: $DB_BACKUP_FILE"
    fi
    
    log ""
    log_warning "You are about to rollback to: $SELECTED_TIMESTAMP"
    log_warning "This will:"
    log "  1. Restore database from backup"
    log "  2. Restore code to previous commit (if available)"
    log "  3. Restore .env configuration (if available)"
    log "  4. Restart containers"
    log ""
    
    echo -n "Are you sure? Type 'yes' to continue: "
    read -r CONFIRM
    
    if [ "$CONFIRM" != "yes" ]; then
        log_info "Rollback cancelled by user"
        exit 0
    fi
    
    log ""
    log "${BLUE}[1/4] Restoring database...${NC}"
    
    # Create backup of current state before rollback
    ROLLBACK_BACKUP_DIR="$BACKUP_DIR/before_rollback_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$ROLLBACK_BACKUP_DIR"
    
    log_info "Creating safety backup before rollback..."
    if $DOCKER_COMPOSE exec -T db mysqldump -uroot -p"$DB_ROOT_PASS" --single-transaction --quick "$DB_NAME" > "$ROLLBACK_BACKUP_DIR/db_backup.sql" 2>>"$LOG_FILE"; then
        log_success "Safety backup created"
    else
        log_warning "Failed to create safety backup, continuing anyway..."
    fi
    
    # Restore database
    log_info "Restoring database from: $DB_BACKUP_FILE"
    if cat "$DB_BACKUP_FILE" | $DOCKER_COMPOSE exec -T db mysql --default-character-set=utf8mb4 -uroot -p"$DB_ROOT_PASS" "$DB_NAME" 2>>"$LOG_FILE"; then
        log_success "Database restored"
    else
        error_exit "Failed to restore database"
    fi
    
    # Restore code
    log ""
    log "${BLUE}[2/4] Restoring code...${NC}"
    
    if [ -f "$COMMIT_BACKUP_FILE" ]; then
        TARGET_COMMIT=$(cat "$COMMIT_BACKUP_FILE")
        log_info "Restoring code to commit: $TARGET_COMMIT"
        
        # Stash current changes
        if ! git diff-index --quiet HEAD -- 2>/dev/null; then
            log_info "Stashing current changes..."
            git stash push -m "Auto-stash before rollback $(date +%Y%m%d_%H%M%S)" 2>&1 | tee -a "$LOG_FILE"
        fi
        
        # Reset to target commit
        if git reset --hard "$TARGET_COMMIT" 2>&1 | tee -a "$LOG_FILE"; then
            log_success "Code restored to: $TARGET_COMMIT"
        else
            log_error "Failed to restore code"
        fi
    else
        log_warning "No commit backup found, skipping code restore"
    fi
    
    # Restore .env
    log ""
    log "${BLUE}[3/4] Restoring configuration...${NC}"
    
    if [ -f "$ENV_BACKUP_FILE" ]; then
        log_info "Restoring .env configuration..."
        cp "$ENV_BACKUP_FILE" .env
        log_success ".env restored"
    else
        log_warning "No .env backup found, keeping current configuration"
    fi
    
    # Restart containers
    log ""
    log "${BLUE}[4/4] Restarting containers...${NC}"
    
    log_info "Rebuilding and restarting containers..."
    $DOCKER_COMPOSE down 2>&1 | tee -a "$LOG_FILE"
    $DOCKER_COMPOSE up -d --build 2>&1 | tee -a "$LOG_FILE"
    
    # Wait for services
    log_info "Waiting for services to be ready..."
    sleep 10
    
    MAX_TRIES=30
    COUNTER=0
    until $DOCKER_COMPOSE exec -T db mysqladmin ping -h localhost -uroot -p"$DB_ROOT_PASS" &>/dev/null; do
        COUNTER=$((COUNTER + 1))
        if [ $COUNTER -gt $MAX_TRIES ]; then
            error_exit "Database did not become ready in time"
        fi
        echo -n "."
        sleep 2
    done
    echo ""
    
    log_success "Containers restarted"
    
    # Summary
    log ""
    log "=========================================="
    log "${GREEN}✓ Rollback completed successfully!${NC}"
    log "=========================================="
    log ""
    log_info "Rolled back to: $SELECTED_TIMESTAMP"
    log_info "Safety backup saved: $ROLLBACK_BACKUP_DIR/"
    log_info "Access panel: http://localhost:8082"
    log ""
    
    exit 0
fi

# ==========================================
# 1. ENVIRONMENT CHECK
# ==========================================
log ""
log "${BLUE}[1/10] Checking environment...${NC}"

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    log_warning "Running as root. This is not recommended."
fi

# Auto-detect docker compose command
DOCKER_COMPOSE=""
if command -v docker &> /dev/null; then
    if docker compose version &> /dev/null 2>&1; then
        DOCKER_COMPOSE="docker compose"
        log_success "Found: docker compose (v2)"
    elif command -v docker-compose &> /dev/null; then
        DOCKER_COMPOSE="docker-compose"
        log_success "Found: docker-compose (v1)"
    else
        error_exit "Neither 'docker compose' nor 'docker-compose' found"
    fi
else
    error_exit "Docker not found. Please install Docker first."
fi

# Check git
if ! command -v git &> /dev/null; then
    error_exit "Git not found. Please install git first."
fi
log_success "Git version: $(git --version | cut -d' ' -f3)"

# Check if we're in project directory
if [ ! -f "docker-compose.yml" ]; then
    error_exit "docker-compose.yml not found. Are you in the project directory?"
fi
log_success "Project directory confirmed"

# ==========================================
# 2. LOAD CONFIGURATION
# ==========================================
log ""
log "${BLUE}[2/10] Loading configuration...${NC}"

# Load .env file
if [ -f .env ]; then
    set -a
    source .env 2>/dev/null || log_warning "Some .env variables failed to load"
    set +a
    log_success ".env file loaded"
    
    DB_USER=${DB_USERNAME:-amnezia}
    DB_PASS=${DB_PASSWORD:-amnezia}
    DB_NAME=${DB_DATABASE:-amnezia_panel}
    DB_ROOT_PASS=${DB_ROOT_PASSWORD:-rootpassword}
else
    log_warning ".env file not found, using defaults"
    DB_USER="amnezia"
    DB_PASS="amnezia"
    DB_NAME="amnezia_panel"
    DB_ROOT_PASS="rootpassword"
fi

log_info "Database: $DB_NAME"
log_info "DB User: $DB_USER"

# ==========================================
# 3. CHECK DOCKER CONTAINERS
# ==========================================
log ""
log "${BLUE}[3/10] Checking Docker containers...${NC}"

# Check if containers exist
if ! $DOCKER_COMPOSE ps | grep -q "amnezia-panel"; then
    log_warning "Containers not found. Starting them..."
    $DOCKER_COMPOSE up -d 2>&1 | tee -a "$LOG_FILE"
    log_info "Waiting for containers to start..."
    sleep 15
fi

# Check if containers are running (flexible check)
CONTAINER_COUNT=$($DOCKER_COMPOSE ps --format json 2>/dev/null | grep -c "amnezia-panel" || echo "0")
if [ "$CONTAINER_COUNT" -lt 2 ]; then
    # Try alternative check
    if ! $DOCKER_COMPOSE ps 2>/dev/null | grep -q "amnezia-panel"; then
        error_exit "Docker containers are not running. Start them with: $DOCKER_COMPOSE up -d"
    fi
fi
log_success "Containers are running"

# Check container health
WEB_STATUS=$($DOCKER_COMPOSE ps web --format json 2>/dev/null | grep -o '"State":"[^"]*"' | cut -d'"' -f4 || echo "unknown")
DB_STATUS=$($DOCKER_COMPOSE ps db --format json 2>/dev/null | grep -o '"State":"[^"]*"' | cut -d'"' -f4 || echo "unknown")

log_info "Web container: $WEB_STATUS"
log_info "DB container: $DB_STATUS"

# Wait for database to be ready
log_info "Waiting for database to be ready..."
MAX_TRIES=30
COUNTER=0
until $DOCKER_COMPOSE exec -T db mysqladmin ping -h localhost -uroot -p"$DB_ROOT_PASS" &>/dev/null; do
    COUNTER=$((COUNTER + 1))
    if [ $COUNTER -gt $MAX_TRIES ]; then
        error_exit "Database did not become ready in time"
    fi
    echo -n "."
    sleep 2
done
echo ""
log_success "Database is ready"

# ==========================================
# 4. BACKUP (if not skipped)
# ==========================================
if [ $SKIP_BACKUP -eq 0 ]; then
    log ""
    log "${BLUE}[4/10] Creating backup...${NC}"
    
    BACKUP_DIR="backups"
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    mkdir -p "$BACKUP_DIR"
    
    # Database backup
    log_info "Backing up database..."
    DB_BACKUP_FILE="$BACKUP_DIR/db_backup_$TIMESTAMP.sql"
    
    if $DOCKER_COMPOSE exec -T db mysqldump -uroot -p"$DB_ROOT_PASS" --single-transaction --quick "$DB_NAME" > "$DB_BACKUP_FILE" 2>>"$LOG_FILE"; then
        BACKUP_SIZE=$(du -h "$DB_BACKUP_FILE" | cut -f1)
        log_success "Database backup created: $DB_BACKUP_FILE ($BACKUP_SIZE)"
    else
        error_exit "Database backup failed"
    fi
    
    # .env backup
    if [ -f .env ]; then
        cp .env "$BACKUP_DIR/.env_backup_$TIMESTAMP"
        log_success "Configuration backup created"
    fi
    
    # Code backup (current commit)
    CURRENT_COMMIT=$(git rev-parse HEAD 2>/dev/null || echo "unknown")
    echo "$CURRENT_COMMIT" > "$BACKUP_DIR/commit_backup_$TIMESTAMP.txt"
    log_info "Current commit: $CURRENT_COMMIT"
else
    log ""
    log "${YELLOW}[4/10] Backup skipped (--skip-backup flag)${NC}"
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    CURRENT_COMMIT=$(git rev-parse HEAD 2>/dev/null || echo "unknown")
fi

# ==========================================
# 5. GIT REPOSITORY CHECK
# ==========================================
log ""
log "${BLUE}[5/10] Checking git repository...${NC}"

if [ ! -d .git ]; then
    error_exit "Not a git repository. Cannot update automatically. Clone from: https://github.com/infosave2007/amneziavpnphp"
fi
log_success "Git repository found"

# Check remote
REMOTE_URL=$(git config --get remote.origin.url || echo "none")
log_info "Remote: $REMOTE_URL"

# Check current branch
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
log_info "Current branch: $CURRENT_BRANCH"

# Check for uncommitted changes
STASHED=0
if ! git diff-index --quiet HEAD -- 2>/dev/null; then
    log_warning "You have uncommitted changes"
    log_info "Stashing changes..."
    git stash push -m "Auto-stash before update $TIMESTAMP" 2>&1 | tee -a "$LOG_FILE"
    STASHED=1
else
    log_success "Working directory is clean"
fi

# ==========================================
# 6. PULL LATEST CHANGES
# ==========================================
log ""
log "${BLUE}[6/10] Pulling latest changes...${NC}"

# Fetch updates
log_info "Fetching from remote..."
git fetch origin 2>&1 | tee -a "$LOG_FILE"

# Check if update available
UPSTREAM=${1:-'@{u}'}
LOCAL=$(git rev-parse @)
REMOTE=$(git rev-parse "$UPSTREAM" 2>/dev/null || echo "$LOCAL")
BASE=$(git merge-base @ "$UPSTREAM" 2>/dev/null || echo "$LOCAL")

if [ "$LOCAL" = "$REMOTE" ]; then
    if [ $FORCE_UPDATE -eq 0 ]; then
        log_success "Already up to date"
        UPDATE_AVAILABLE=0
    else
        log_warning "Forcing update even though already up to date"
        UPDATE_AVAILABLE=1
    fi
elif [ "$LOCAL" = "$BASE" ]; then
    log_info "New updates available"
    UPDATE_AVAILABLE=1
elif [ "$REMOTE" = "$BASE" ]; then
    log_warning "Local commits ahead of remote. Pull skipped."
    UPDATE_AVAILABLE=0
else
    log_warning "Branches have diverged"
    UPDATE_AVAILABLE=1
fi

if [ $UPDATE_AVAILABLE -eq 1 ]; then
    log_info "Pulling changes..."
    git pull origin "$CURRENT_BRANCH" 2>&1 | tee -a "$LOG_FILE"
    
    NEW_COMMIT=$(git rev-parse HEAD)
    if [ "$CURRENT_COMMIT" != "$NEW_COMMIT" ]; then
        log_success "Updated from $CURRENT_COMMIT to $NEW_COMMIT"
        
        # Show changelog
        log ""
        log_info "Changes:"
        git log --oneline "$CURRENT_COMMIT..$NEW_COMMIT" | head -n 10 | tee -a "$LOG_FILE"
    fi
else
    NEW_COMMIT="$CURRENT_COMMIT"
fi

# ==========================================
# 7. INSTALL DEPENDENCIES
# ==========================================
log ""
log "${BLUE}[7/10] Installing dependencies...${NC}"

log_info "Running composer install..."
if $DOCKER_COMPOSE exec -T web composer install --no-interaction --prefer-dist --optimize-autoloader 2>&1 | tee -a "$LOG_FILE" | grep -v "Warning"; then
    log_success "Dependencies installed"
else
    log_warning "Composer install completed with warnings (check log)"
fi

# ==========================================
# 8. APPLY MIGRATIONS
# ==========================================
log ""
log "${BLUE}[8/10] Applying database migrations...${NC}"

# Get list of migration files
MIGRATIONS=$(ls migrations/*.sql 2>/dev/null | sort || echo "")

if [ -z "$MIGRATIONS" ]; then
    log_warning "No migration files found"
else
    # Create migrations tracking table
    log_info "Ensuring migrations table exists..."
    $DOCKER_COMPOSE exec -T db mysql --default-character-set=utf8mb4 -uroot -p"$DB_ROOT_PASS" "$DB_NAME" <<EOF 2>>"$LOG_FILE"
CREATE TABLE IF NOT EXISTS schema_migrations (
    id INT PRIMARY KEY AUTO_INCREMENT,
    filename VARCHAR(255) UNIQUE NOT NULL,
    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    checksum VARCHAR(64),
    INDEX idx_filename (filename)
);
EOF
    
    # Detect legacy installs missing baseline migration records
    LEGACY_BASELINE_CHECK=$($DOCKER_COMPOSE exec -T db mysql --default-character-set=utf8mb4 -uroot -p"$DB_ROOT_PASS" "$DB_NAME" -sN -e "SELECT COUNT(*) FROM schema_migrations WHERE filename = '010_add_monitoring_translations.sql';" 2>/dev/null || echo "0")
    if [ "$LEGACY_BASELINE_CHECK" = "0" ]; then
        HAS_TRANSLATIONS_LOCALE=$($DOCKER_COMPOSE exec -T db mysql --default-character-set=utf8mb4 -uroot -p"$DB_ROOT_PASS" "$DB_NAME" -sN -e "SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'translations' AND COLUMN_NAME = 'locale';" 2>/dev/null || echo "0")
        HAS_TRANSLATIONS_LANGUAGE_CODE=$($DOCKER_COMPOSE exec -T db mysql --default-character-set=utf8mb4 -uroot -p"$DB_ROOT_PASS" "$DB_NAME" -sN -e "SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'translations' AND COLUMN_NAME = 'language_code';" 2>/dev/null || echo "0")
        if [ "$HAS_TRANSLATIONS_LOCALE" != "0" ] && [ "$HAS_TRANSLATIONS_LANGUAGE_CODE" = "0" ]; then
            log_warning "Detected legacy install without migration records. Seeding baseline entries..."
            $DOCKER_COMPOSE exec -T db mysql --default-character-set=utf8mb4 -uroot -p"$DB_ROOT_PASS" "$DB_NAME" -e "INSERT IGNORE INTO schema_migrations (filename) VALUES \
            ('000_create_user.sql'),('001_init.sql'),('002_translations_ru.sql'),('003_translations_es.sql'),('004_translations_de.sql'),('005_translations_fr.sql'),('006_translations_zh.sql'),('007_add_traffic_limit.sql'),('008_add_panel_imports.sql'),('009_add_server_metrics.sql'),('010_add_monitoring_translations.sql');" 2>>"$LOG_FILE" || true
            $DOCKER_COMPOSE exec -T db mysql --default-character-set=utf8mb4 -uroot -p"$DB_ROOT_PASS" "$DB_NAME" -e "INSERT IGNORE INTO user_roles (name, display_name, description, permissions) VALUES \
            ('admin','Administrator','Full access to all features', JSON_ARRAY('*')),\
            ('manager','Manager','Can manage servers and clients', JSON_ARRAY('servers.view','servers.create','servers.edit','clients.view','clients.create','clients.edit','clients.delete')),\
            ('viewer','Viewer','Can only view own clients', JSON_ARRAY('clients.view_own','clients.download_own'));" 2>>"$LOG_FILE" || true
            $DOCKER_COMPOSE exec -T db mysql --default-character-set=utf8mb4 -uroot -p"$DB_ROOT_PASS" "$DB_NAME" -e "INSERT IGNORE INTO ldap_group_mappings (ldap_group, role_name, description) VALUES \
            ('vpn-admins','admin','VPN administrators with full access'),\
            ('vpn-managers','manager','VPN managers who can create and manage clients'),\
            ('vpn-users','viewer','Regular VPN users with view-only access');" 2>>"$LOG_FILE" || true
            log_success "Baseline migration entries seeded"
        fi
    fi

    # Apply each migration
    APPLIED_COUNT=0
    SKIPPED_COUNT=0
    
    for migration in $MIGRATIONS; do
        FILENAME=$(basename "$migration")
        
        # Check if already applied
        ALREADY_APPLIED=$($DOCKER_COMPOSE exec -T db mysql --default-character-set=utf8mb4 -uroot -p"$DB_ROOT_PASS" "$DB_NAME" -sN -e "SELECT COUNT(*) FROM schema_migrations WHERE filename = '$FILENAME';" 2>/dev/null || echo "0")
        
        if [ "$ALREADY_APPLIED" = "0" ]; then
            log_info "Applying: $FILENAME"
            
            # Apply migration
            if cat "$migration" | $DOCKER_COMPOSE exec -T db mysql --default-character-set=utf8mb4 -uroot -p"$DB_ROOT_PASS" "$DB_NAME" 2>>"$LOG_FILE"; then
                # Calculate checksum
                CHECKSUM=$(sha256sum "$migration" | cut -d' ' -f1)
                
                # Mark as applied
                $DOCKER_COMPOSE exec -T db mysql --default-character-set=utf8mb4 -uroot -p"$DB_ROOT_PASS" "$DB_NAME" -e "INSERT INTO schema_migrations (filename, checksum) VALUES ('$FILENAME', '$CHECKSUM');" 2>>"$LOG_FILE"
                
                log_success "Applied: $FILENAME"
                APPLIED_COUNT=$((APPLIED_COUNT + 1))
            else
                # Check error log for "already exists" errors (idempotent migrations)
                LAST_ERROR=$(tail -30 "$LOG_FILE" | grep -i "ERROR.*already exists\|ERROR.*Duplicate\|ERROR.*Table.*already" || echo "")
                
                if [ -n "$LAST_ERROR" ]; then
                    log_warning "Migration $FILENAME skipped (tables already exist)"
                    
                    # Mark as applied to prevent re-running
                    CHECKSUM=$(sha256sum "$migration" | cut -d' ' -f1)
                    $DOCKER_COMPOSE exec -T db mysql --default-character-set=utf8mb4 -uroot -p"$DB_ROOT_PASS" "$DB_NAME" -e "INSERT IGNORE INTO schema_migrations (filename, checksum) VALUES ('$FILENAME', '$CHECKSUM');" 2>>"$LOG_FILE"
                    SKIPPED_COUNT=$((SKIPPED_COUNT + 1))
                else
                    log_error "Failed to apply: $FILENAME"
                    log_warning "Check $LOG_FILE for details. Continuing with next migration..."
                    SKIPPED_COUNT=$((SKIPPED_COUNT + 1))
                fi
            fi
        else
            SKIPPED_COUNT=$((SKIPPED_COUNT + 1))
        fi
    done
    
    if [ $APPLIED_COUNT -eq 0 ]; then
        log_success "All migrations already applied ($SKIPPED_COUNT skipped)"
    else
        log_success "Applied $APPLIED_COUNT new migration(s), skipped $SKIPPED_COUNT"
    fi
fi

# ==========================================
# 9. RESTART CONTAINERS
# ==========================================
log ""
log "${BLUE}[9/10] Restarting containers...${NC}"

# Check if cron is configured in container
log_info "Checking cron configuration..."
CRON_CONFIGURED=$($DOCKER_COMPOSE exec -T web test -f /etc/cron.d/amnezia-cron && echo "1" || echo "0")

if [ "$CRON_CONFIGURED" = "0" ]; then
    log_warning "Cron not configured in container, rebuilding required..."
    DOCKERFILE_CHANGED=1
else
    log_success "Cron is configured"
    DOCKERFILE_CHANGED=0
fi

# Check if Dockerfile was modified
if [ "$CURRENT_COMMIT" != "$NEW_COMMIT" ]; then
    if git diff --name-only "$CURRENT_COMMIT" "$NEW_COMMIT" 2>/dev/null | grep -q "Dockerfile\|bin/monitor_metrics.sh\|bin/collect_metrics.php"; then
        DOCKERFILE_CHANGED=1
        log_info "Dockerfile or critical scripts changed, rebuilding..."
    fi
fi

if [ $DOCKERFILE_CHANGED -eq 1 ]; then
    log_info "Rebuilding web container..."
    $DOCKER_COMPOSE build --no-cache web 2>&1 | tee -a "$LOG_FILE" | grep -v "^#"
    
    log_info "Restarting all containers..."
    $DOCKER_COMPOSE down 2>&1 | tee -a "$LOG_FILE"
    $DOCKER_COMPOSE up -d 2>&1 | tee -a "$LOG_FILE"
    
    log_info "Waiting for services to start..."
    sleep 15
    
    # Wait for database
    MAX_TRIES=30
    COUNTER=0
    until $DOCKER_COMPOSE exec -T db mysqladmin ping -h localhost -uroot -p"$DB_ROOT_PASS" &>/dev/null; do
        COUNTER=$((COUNTER + 1))
        if [ $COUNTER -gt $MAX_TRIES ]; then
            log_warning "Database took longer than expected to start"
            break
        fi
        echo -n "."
        sleep 2
    done
    echo ""
    
    log_success "Containers rebuilt and restarted"
else
    log_info "Restarting web container..."
    $DOCKER_COMPOSE restart web 2>&1 | tee -a "$LOG_FILE"
    sleep 5
fi

# Check if web is responding
log_info "Checking web container health..."
if $DOCKER_COMPOSE exec -T web php -v &>/dev/null; then
    PHP_VERSION=$($DOCKER_COMPOSE exec -T web php -v | head -n1)
    log_success "Web container is healthy: $PHP_VERSION"
else
    log_warning "Web container may not be fully ready"
fi

# Check if metrics collector is running
log_info "Checking metrics collector..."
METRICS_PID=$($DOCKER_COMPOSE exec -T web cat /var/run/collect_metrics.pid 2>/dev/null || echo "")
if [ -n "$METRICS_PID" ]; then
    if $DOCKER_COMPOSE exec -T web ps -p "$METRICS_PID" &>/dev/null; then
        log_success "Metrics collector is running (PID: $METRICS_PID)"
    else
        log_warning "Metrics collector PID file exists but process not found, starting..."
        $DOCKER_COMPOSE exec -d web /bin/bash /var/www/html/bin/monitor_metrics.sh
        sleep 3
        NEW_PID=$($DOCKER_COMPOSE exec -T web cat /var/run/collect_metrics.pid 2>/dev/null || echo "")
        if [ -n "$NEW_PID" ]; then
            log_success "Metrics collector started (PID: $NEW_PID)"
        fi
    fi
else
    log_warning "Metrics collector not running, starting now..."
    $DOCKER_COMPOSE exec -d web /bin/bash /var/www/html/bin/monitor_metrics.sh
    sleep 3
    NEW_PID=$($DOCKER_COMPOSE exec -T web cat /var/run/collect_metrics.pid 2>/dev/null || echo "")
    if [ -n "$NEW_PID" ]; then
        log_success "Metrics collector started (PID: $NEW_PID)"
    else
        log_warning "Failed to start metrics collector. Check: docker-compose exec web tail /var/log/metrics_monitor.log"
    fi
fi

# ==========================================
# 10. RESTORE STASHED CHANGES
# ==========================================
log ""
log "${BLUE}[10/10] Finalizing...${NC}"

if [ $STASHED -eq 1 ]; then
    log_info "Restoring stashed changes..."
    if git stash pop 2>&1 | tee -a "$LOG_FILE"; then
        log_success "Stashed changes restored"
    else
        log_warning "Conflict when restoring changes. Resolve manually with: git stash list && git stash pop"
    fi
fi

# ==========================================
# SUMMARY
# ==========================================
log ""
log "=========================================="
log "${GREEN}✓ Update completed successfully!${NC}"
log "=========================================="
log ""
log_info "Summary:"
log "  - Start time: $START_TIME"
log "  - End time: $(date)"
log "  - Log file: $LOG_FILE"

if [ $SKIP_BACKUP -eq 0 ]; then
    log ""
    log_info "Backup location: $BACKUP_DIR/"
    log "  - Database: db_backup_$TIMESTAMP.sql ($BACKUP_SIZE)"
    if [ -f "$BACKUP_DIR/.env_backup_$TIMESTAMP" ]; then
        log "  - Config: .env_backup_$TIMESTAMP"
    fi
    log "  - Commit: $CURRENT_COMMIT"
fi

log ""
log_info "Access panel: http://localhost:8082"
log ""

if [ $SKIP_BACKUP -eq 0 ]; then
    log_info "To rollback in case of issues:"
    log "  $0 --rollback"
    log "  or manually:"
    log "  1. $DOCKER_COMPOSE down"
    log "  2. cat $BACKUP_DIR/db_backup_$TIMESTAMP.sql | $DOCKER_COMPOSE exec -T db mysql --default-character-set=utf8mb4 -uroot -p\$DB_ROOT_PASS $DB_NAME"
    log "  3. git reset --hard $CURRENT_COMMIT"
    log "  4. $DOCKER_COMPOSE up -d"
    log ""
else
    log_warning "Backup was skipped; ensure you have a recent SQL dump before rolling back."
    log_info "To rollback in case of issues:"
    log "  $0 --rollback"
    log "  or manually:"
    log "  1. $DOCKER_COMPOSE down"
    log "  2. Restore database from your backup"
    log "  3. git reset --hard $CURRENT_COMMIT"
    log "  4. $DOCKER_COMPOSE up -d"
    log ""
fi

log_success "Update completed at $(date)"
