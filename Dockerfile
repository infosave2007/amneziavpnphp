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
RUN composer install --no-dev --optimize-autoloader

# Configure Apache
COPY apache.conf /etc/apache2/sites-available/000-default.conf

# Set permissions
RUN chown -R www-data:www-data /var/www/html \
    && chmod -R 755 /var/www/html/public

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
# Start metrics collector on container startup\n\
/bin/bash /var/www/html/bin/monitor_metrics.sh\n\
apache2-foreground' > /start.sh \
    && chmod +x /start.sh

# Expose port 80
EXPOSE 80

CMD ["/start.sh"]
