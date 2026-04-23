FROM php:8.2-apache

# Install dependencies including LDAP
RUN apt-get update && apt-get install -y \
    git \
    curl \
    libpng-dev \
    libonig-dev \
    libxml2-dev \
    zip \
    unzip \
    sshpass \
    openssh-client \
    qrencode \
    cron \
    libldap2-dev \
    docker.io \
    && docker-php-ext-configure ldap --with-libdir=lib/x86_64-linux-gnu/ \
    && docker-php-ext-install pdo_mysql mbstring exif pcntl bcmath gd ldap \
    && a2enmod rewrite \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install Composer
COPY --from=composer:latest /usr/bin/composer /usr/bin/composer

# Set working directory
WORKDIR /var/www/html

# Copy project files
COPY . /var/www/html

# Install PHP dependencies
RUN git config --global --add safe.directory /var/www/html \
  && composer config --global audit.block-insecure false \
  && composer install --no-dev --optimize-autoloader --no-security-blocking

# Configure Apache
COPY apache.conf /etc/apache2/sites-available/000-default.conf

# Set permissions and create writable directories
RUN mkdir -p /var/www/html/backups /var/www/html/logs \
    && chown -R www-data:www-data /var/www/html \
    && chmod -R 755 /var/www/html/public \
    && chmod 775 /var/www/html/backups /var/www/html/logs

# Setup cron jobs
RUN echo "0 * * * * www-data cd /var/www/html && /usr/local/bin/php bin/check_expired_clients.php >> /var/log/cron.log 2>&1" > /etc/cron.d/amnezia-cron \
    && echo "0 * * * * www-data cd /var/www/html && /usr/local/bin/php bin/check_traffic_limits.php >> /var/log/cron.log 2>&1" >> /etc/cron.d/amnezia-cron \
    && echo "*/30 * * * * www-data cd /var/www/html && /usr/local/bin/php bin/sync_ldap_users.php >> /var/log/ldap_sync.log 2>&1" >> /etc/cron.d/amnezia-cron \
    && echo "*/3 * * * * root /bin/bash /var/www/html/bin/monitor_metrics.sh >> /var/log/metrics_monitor.log 2>&1" >> /etc/cron.d/amnezia-cron \
    && chmod 0644 /etc/cron.d/amnezia-cron \
    && crontab /etc/cron.d/amnezia-cron \
    && touch /var/log/cron.log \
    && touch /var/log/metrics_monitor.log \
    && touch /var/log/metrics_collector.log \
    && touch /var/log/ldap_sync.log

# Make monitor script executable
RUN chmod +x /var/www/html/bin/monitor_metrics.sh

# Create startup script
RUN echo '#!/bin/bash\n\
service cron start\n\
# Ensure writable directories exist with correct ownership\n\
mkdir -p /var/www/html/backups /var/www/html/logs\n\
chown www-data:www-data /var/www/html/backups /var/www/html/logs\n\
chmod 775 /var/www/html/backups /var/www/html/logs\n\
# Ensure www-data can talk to host docker socket if mounted\n\
if [ -S /var/run/docker.sock ]; then\n\
  SOCK_GID=$(stat -c %g /var/run/docker.sock)\n\
  if ! getent group docker >/dev/null; then\n\
    groupadd -g "$SOCK_GID" docker || true\n\
  fi\n\
  usermod -aG docker www-data || true\n\
fi\n\
# Start metrics collector on container startup\n\
/bin/bash /var/www/html/bin/monitor_metrics.sh\n\
apache2-foreground' > /start.sh \
    && chmod +x /start.sh

# Expose port 80
EXPOSE 80

CMD ["/start.sh"]
