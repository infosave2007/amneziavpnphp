#!/usr/bin/env bash
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
MIGRATION="$ROOT/migrations/072_repair_mojibake_translations.sql"
: "${MYSQL_DEFAULTS_FILE:?Set MYSQL_DEFAULTS_FILE to a mode-600 mysql client option file with test-database privileges}"
[ -r "$MYSQL_DEFAULTS_FILE" ] || { echo "MYSQL_DEFAULTS_FILE is not readable" >&2; exit 2; }
command -v mysql >/dev/null || { echo "mysql client is required" >&2; exit 2; }

TEST_DB="amnezia_encoding_test_${PPID}_$$"
case "$TEST_DB" in (*[!A-Za-z0-9_]*) echo "unsafe test database name" >&2; exit 2;; esac
MYSQL=(mysql --defaults-extra-file="$MYSQL_DEFAULTS_FILE" --default-character-set=utf8mb4)
owned_by_test=0
cleanup() {
  if [ "$owned_by_test" = 1 ]; then
    "${MYSQL[@]}" -e "DROP DATABASE $TEST_DB" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

"${MYSQL[@]}" -e "CREATE DATABASE $TEST_DB CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
owned_by_test=1
"${MYSQL[@]}" "$TEST_DB" <<'SQL'
CREATE TABLE translations (
  id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  locale VARCHAR(5) NOT NULL,
  category VARCHAR(50) NOT NULL,
  key_name VARCHAR(100) NOT NULL,
  translation TEXT NOT NULL,
  UNIQUE KEY unique_translation(locale,category,key_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE languages (
  code VARCHAR(10) NOT NULL PRIMARY KEY,
  native_name VARCHAR(50) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Genuine latin1-client double encoding and its expected UTF-8 value.
INSERT INTO translations(locale,category,key_name,translation) VALUES
('ru','fixture','broken',CONVERT(0xC390C5B8C391E282ACC390C2B8C390C2B2C390C2B5C391E2809A USING utf8mb4)),
-- Marker-bearing valid/mixed custom rows must remain untouched.
('zh','fixture','valid_latin_chinese','ä中文'),
('ru','fixture','valid_literal_marker','Ð валидный текст'),
('ru','fixture','mixed','Нормально ÐŸÑ€Ð¸Ð²ÐµÑ‚'),
('fr','fixture','valid_c_tilde','Ã Paris');
INSERT INTO languages(code,native_name) VALUES
('es',CONVERT(0x45737061C383C2B16F6C USING utf8mb4)),
('zh-Hant',CONVERT(0x45737061C383C2B16F6C USING utf8mb4)),
('zh','ä中文');
CREATE TABLE expected_unchanged AS
SELECT id, HEX(translation) value_hex FROM translations WHERE key_name <> 'broken';
CREATE TABLE expected_language_unchanged AS
SELECT code, HEX(native_name) value_hex FROM languages WHERE code = 'zh';
SQL

"${MYSQL[@]}" "$TEST_DB" < "$MIGRATION"
read -r repaired_translation repaired_language unchanged_translation unchanged_language backup_translation backup_language < <(
  "${MYSQL[@]}" "$TEST_DB" -Nse "SELECT
    (SELECT COUNT(*) FROM translations WHERE key_name='broken' AND HEX(translation)='D09FD180D0B8D0B2D0B5D182'),
    (SELECT COUNT(*) FROM languages WHERE code IN ('es','zh-Hant') AND HEX(native_name)='45737061C3B16F6C'),
    (SELECT COUNT(*) FROM expected_unchanged e JOIN translations t ON t.id=e.id AND HEX(t.translation)=e.value_hex),
    (SELECT COUNT(*) FROM expected_language_unchanged e JOIN languages l ON l.code=e.code AND HEX(l.native_name)=e.value_hex),
    (SELECT COUNT(*) FROM translation_encoding_backup_072),
    (SELECT COUNT(*) FROM language_encoding_backup_072);"
)
[ "$repaired_translation" = 1 ]
[ "$repaired_language" = 2 ]
[ "$unchanged_translation" = 4 ]
[ "$unchanged_language" = 1 ]
[ "$backup_translation" = 1 ]
[ "$backup_language" = 2 ]

digest_before=$("${MYSQL[@]}" "$TEST_DB" -Nse "SET SESSION group_concat_max_len=1048576; SELECT SHA2(GROUP_CONCAT(CONCAT(id,':',HEX(translation)) ORDER BY id SEPARATOR '|'),256) FROM translations; SELECT SHA2(GROUP_CONCAT(CONCAT(code,':',HEX(native_name)) ORDER BY code SEPARATOR '|'),256) FROM languages;")
"${MYSQL[@]}" "$TEST_DB" < "$MIGRATION"
digest_after=$("${MYSQL[@]}" "$TEST_DB" -Nse "SET SESSION group_concat_max_len=1048576; SELECT SHA2(GROUP_CONCAT(CONCAT(id,':',HEX(translation)) ORDER BY id SEPARATOR '|'),256) FROM translations; SELECT SHA2(GROUP_CONCAT(CONCAT(code,':',HEX(native_name)) ORDER BY code SEPARATOR '|'),256) FROM languages;")
[ "$digest_before" = "$digest_after" ]

"${MYSQL[@]}" -e "DROP DATABASE $TEST_DB"
remaining=$("${MYSQL[@]}" -Nse "SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name='${TEST_DB}'")
[ "$remaining" = 0 ]
owned_by_test=0
printf 'PASS encoding_mysql_integration repaired=3 valid_or_mixed_preserved=5 backups=3 idempotent=true database_removed=true\n'
