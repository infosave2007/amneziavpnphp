#!/usr/bin/env bash
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
UPDATE="$ROOT/update.sh"
MIGRATION="$ROOT/migrations/072_repair_mojibake_translations.sql"

bash -n "$UPDATE"
python3 - "$UPDATE" "$MIGRATION" "$ROOT" <<'PY'
from pathlib import Path
import sys

update = Path(sys.argv[1]).read_text(encoding="utf-8")
migration = Path(sys.argv[2]).read_text(encoding="utf-8")
root = Path(sys.argv[3])

mysql_calls = [line for line in update.splitlines() if "exec -T db mysql " in line]
assert mysql_calls, "update.sh has no mysql client calls"
assert all("--default-character-set=utf8mb4" in line for line in mysql_calls), (
    "every update.sh mysql invocation must set utf8mb4 explicitly"
)

for marker in (
    "translation_encoding_backup_072",
    "language_encoding_backup_072",
    "HEX(t.translation) = b.original_hex",
    "HEX(l.native_name) = b.original_hex",
    "CONVERT(CAST(CONVERT(translation USING latin1) AS BINARY) USING utf8mb4)",
    "HEX(c.original_translation) = HEX(",
    "HEX(c.original_native_name) = HEX(",
):
    assert marker in migration, f"missing guarded repair contract: {marker}"

source = (root / "migrations/002_translations_ru.sql").read_text(encoding="utf-8")
assert "Панель управления" in source, "Russian migration source is not valid expected UTF-8"

for readme_name in ("README.md", "README_RU.md", "README_ZH.md", "migrations/README.md"):
    text = (root / readme_name).read_text(encoding="utf-8")
    for line in text.splitlines():
        if "exec -T db mysql " in line or "exec db mysql " in line:
            assert "--default-character-set=utf8mb4" in line, f"{readme_name}: mysql example lacks utf8mb4"

print(f"PASS explicit_update_mysql_calls={len(mysql_calls)} guarded_backups=2 utf8_source=PASS docs=PASS")
PY
