-- Add persistent AIVPN raw/offset counters for monotonic traffic totals across server restarts.

ALTER TABLE vpn_clients
  ADD COLUMN aivpn_raw_bytes_in BIGINT UNSIGNED NOT NULL DEFAULT 0 AFTER bytes_received,
  ADD COLUMN aivpn_raw_bytes_out BIGINT UNSIGNED NOT NULL DEFAULT 0 AFTER aivpn_raw_bytes_in,
  ADD COLUMN aivpn_offset_bytes_in BIGINT UNSIGNED NOT NULL DEFAULT 0 AFTER aivpn_raw_bytes_out,
  ADD COLUMN aivpn_offset_bytes_out BIGINT UNSIGNED NOT NULL DEFAULT 0 AFTER aivpn_offset_bytes_in;
