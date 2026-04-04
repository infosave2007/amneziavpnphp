ALTER TABLE vpn_clients ADD COLUMN speed_up BIGINT DEFAULT 0 AFTER current_speed;
ALTER TABLE vpn_clients ADD COLUMN speed_down BIGINT DEFAULT 0 AFTER speed_up;
-- We can drop current_speed later or keep it as total
