ALTER TABLE vpn_clients ADD COLUMN current_speed BIGINT DEFAULT 0 AFTER traffic_limit;
