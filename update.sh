#!/bin/bash

# Amnezia VPN Panel - Auto Update Script
# Usage: ./update.sh

set -e  # Exit on error

echo "=========================================="
echo "  Amnezia VPN Panel - Auto Update"
echo "=========================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Auto-detect docker compose command
if command -v docker-compose &> /dev/null; then
    DOCKER_COMPOSE="docker-compose"
elif docker compose version &> /dev/null; then
    DOCKER_COMPOSE="docker compose"
else
    echo -e "${RED}Error: Neither 'docker compose' nor 'docker-compose' found${NC}"
    exit 1
fi

# Load DB credentials from .env
if [ -f .env ]; then
    # Source .env file safely
    set -a
    source .env
    set +a
    DB_USER=${DB_USERNAME:-amnezia}
    DB_PASS=${DB_PASSWORD:-amnezia}
    DB_ROOT_PASS=${DB_ROOT_PASSWORD:-rootpassword}
else
    echo -e "${YELLOW}⚠ .env file not found, using defaults${NC}"
    DB_USER="amnezia"
    DB_PASS="amnezia"
    DB_ROOT_PASS="rootpassword"
fi

# Check if docker compose is running
if ! $DOCKER_COMPOSE ps | grep -q "Up"; then
    echo -e "${RED}Error: Docker containers are not running${NC}"
    echo "Please start containers first: $DOCKER_COMPOSE up -d"
    exit 1
fi

# 1. Create backup directory
BACKUP_DIR="backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
mkdir -p $BACKUP_DIR

echo -e "${YELLOW}[1/7] Creating backup...${NC}"
# Backup database (try root first, fallback to regular user)
if $DOCKER_COMPOSE exec -T db mysqldump -uroot -p$DB_ROOT_PASS amnezia_panel > "$BACKUP_DIR/db_backup_$TIMESTAMP.sql" 2>/dev/null; then
    echo -e "${GREEN}✓ Database backup created: $BACKUP_DIR/db_backup_$TIMESTAMP.sql${NC}"
elif $DOCKER_COMPOSE exec db mysqldump -uroot -p$DB_ROOT_PASS amnezia_panel > "$BACKUP_DIR/db_backup_$TIMESTAMP.sql" 2>/dev/null; then
    echo -e "${GREEN}✓ Database backup created: $BACKUP_DIR/db_backup_$TIMESTAMP.sql${NC}"
else
    echo -e "${RED}✗ Database backup failed${NC}"
    exit 1
fi

# Backup .env file
if [ -f .env ]; then
    cp .env "$BACKUP_DIR/.env_backup_$TIMESTAMP"
    echo -e "${GREEN}✓ Configuration backup created${NC}"
fi

# 2. Check for git repository
echo ""
echo -e "${YELLOW}[2/7] Checking git repository...${NC}"
if [ ! -d .git ]; then
    echo -e "${RED}✗ Not a git repository. Cannot update automatically.${NC}"
    echo "Please clone from: https://github.com/infosave2007/amneziavpnphp"
    exit 1
fi

# 3. Check for uncommitted changes
if ! git diff-index --quiet HEAD -- 2>/dev/null; then
    echo -e "${YELLOW}⚠ You have uncommitted changes${NC}"
    echo "Stashing changes..."
    git stash push -m "Auto-stash before update $TIMESTAMP"
    STASHED=1
else
    STASHED=0
    echo -e "${GREEN}✓ Working directory is clean${NC}"
fi

# 4. Pull latest changes
echo ""
echo -e "${YELLOW}[3/7] Pulling latest changes from git...${NC}"
CURRENT_COMMIT=$(git rev-parse HEAD)
git fetch origin
git pull origin master

NEW_COMMIT=$(git rev-parse HEAD)

if [ "$CURRENT_COMMIT" = "$NEW_COMMIT" ]; then
    echo -e "${GREEN}✓ Already up to date${NC}"
else
    echo -e "${GREEN}✓ Updated from $CURRENT_COMMIT to $NEW_COMMIT${NC}"
fi

# 5. Install/update dependencies
echo ""
echo -e "${YELLOW}[4/7] Installing dependencies...${NC}"
$DOCKER_COMPOSE exec web composer install --no-interaction --prefer-dist 2>&1 | grep -v "Warning"
echo -e "${GREEN}✓ Dependencies installed${NC}"

# 6. Apply migrations
echo ""
echo -e "${YELLOW}[5/7] Applying database migrations...${NC}"

# Get list of migration files
MIGRATIONS=$(ls migrations/*.sql 2>/dev/null | sort)

if [ -z "$MIGRATIONS" ]; then
    echo -e "${YELLOW}⚠ No migration files found${NC}"
else
    # Create migrations tracking table if not exists
    $DOCKER_COMPOSE exec -T db mysql -uroot -p$DB_ROOT_PASS amnezia_panel <<EOF 2>/dev/null || \
    $DOCKER_COMPOSE exec db mysql -uroot -p$DB_ROOT_PASS amnezia_panel <<EOF 2>/dev/null
CREATE TABLE IF NOT EXISTS schema_migrations (
    id INT PRIMARY KEY AUTO_INCREMENT,
    filename VARCHAR(255) UNIQUE NOT NULL,
    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_filename (filename)
);
EOF
    
    # Apply each migration
    APPLIED_COUNT=0
    for migration in $MIGRATIONS; do
        FILENAME=$(basename "$migration")
        
        # Check if already applied
        ALREADY_APPLIED=$($DOCKER_COMPOSE exec -T db mysql -uroot -p$DB_ROOT_PASS amnezia_panel -sN 2>/dev/null <<EOF || echo "0"
SELECT COUNT(*) FROM schema_migrations WHERE filename = '$FILENAME';
EOF
)
        
        if [ "$ALREADY_APPLIED" = "0" ] || [ -z "$ALREADY_APPLIED" ]; then
            echo "  Applying: $FILENAME"
            
            # Apply migration (try -T first, fallback without)
            if cat "$migration" | $DOCKER_COMPOSE exec -T db mysql -uroot -p$DB_ROOT_PASS amnezia_panel 2>/dev/null || \
               cat "$migration" | $DOCKER_COMPOSE exec db mysql -uroot -p$DB_ROOT_PASS amnezia_panel 2>/dev/null; then
                # Mark as applied
                $DOCKER_COMPOSE exec -T db mysql -uroot -p$DB_ROOT_PASS amnezia_panel -e "INSERT INTO schema_migrations (filename) VALUES ('$FILENAME');" 2>/dev/null || \
                $DOCKER_COMPOSE exec db mysql -uroot -p$DB_ROOT_PASS amnezia_panel -e "INSERT INTO schema_migrations (filename) VALUES ('$FILENAME');" 2>/dev/null
                echo -e "  ${GREEN}✓ Applied: $FILENAME${NC}"
                APPLIED_COUNT=$((APPLIED_COUNT + 1))
            else
                echo -e "  ${YELLOW}⚠ Skipped: $FILENAME (may be already applied)${NC}"
            fi
        fi
    done
    
    if [ $APPLIED_COUNT -eq 0 ]; then
        echo -e "${GREEN}✓ All migrations already applied${NC}"
    else
        echo -e "${GREEN}✓ Applied $APPLIED_COUNT new migration(s)${NC}"
    fi
fi

# 7. Restart containers
echo ""
echo -e "${YELLOW}[6/7] Restarting containers...${NC}"
$DOCKER_COMPOSE restart web 2>&1 | grep -v "Warning"
echo -e "${GREEN}✓ Containers restarted${NC}"

# 8. Restore stashed changes
if [ $STASHED -eq 1 ]; then
    echo ""
    echo -e "${YELLOW}[7/7] Restoring stashed changes...${NC}"
    if git stash pop; then
        echo -e "${GREEN}✓ Stashed changes restored${NC}"
    else
        echo -e "${YELLOW}⚠ Conflict when restoring changes. Please resolve manually:${NC}"
        echo "  git stash list"
        echo "  git stash pop"
    fi
else
    echo ""
    echo -e "${YELLOW}[7/7] No stashed changes to restore${NC}"
fi

# Summary
echo ""
echo "=========================================="
echo -e "${GREEN}✓ Update completed successfully!${NC}"
echo "=========================================="
echo ""
echo "Backup location: $BACKUP_DIR/"
echo "  - Database: db_backup_$TIMESTAMP.sql"
if [ -f "$BACKUP_DIR/.env_backup_$TIMESTAMP" ]; then
    echo "  - Config: .env_backup_$TIMESTAMP"
fi
echo ""
echo "To rollback in case of issues:"
echo "  1. Stop containers: $DOCKER_COMPOSE down"
echo "  2. Restore database: cat $BACKUP_DIR/db_backup_$TIMESTAMP.sql | $DOCKER_COMPOSE exec -T db mysql -uroot -p$DB_ROOT_PASS amnezia_panel"
echo "  3. Restore code: git reset --hard $CURRENT_COMMIT"
echo "  4. Start containers: $DOCKER_COMPOSE up -d"
echo ""
