-- Add dns_servers column to vpn_servers table if missing
-- Needed for correct configuration regeneration

SET @dbname = DATABASE();
SET @tablename = "vpn_servers";
SET @columnname = "dns_servers";
SET @preparedStatement = (SELECT IF(
  (
    SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE
      (table_name = @tablename)
      AND (table_schema = @dbname)
      AND (column_name = @columnname)
  ) > 0,
  "SELECT 1",
  "ALTER TABLE vpn_servers ADD COLUMN dns_servers VARCHAR(255) DEFAULT '1.1.1.1, 1.0.0.1'"
));
PREPARE alterIfNotExists FROM @preparedStatement;
EXECUTE alterIfNotExists;
DEALLOCATE PREPARE alterIfNotExists;
