-- Repair text that was double-encoded when UTF-8 migration files were fed to a
-- mysql client using its latin1 default. Candidate rows must pass a lossless
-- byte round trip before they are backed up or changed, so valid and mixed
-- custom UTF-8 text remains untouched. Every changed value is retained
-- byte-for-byte in a backup table before repair.
CREATE TABLE IF NOT EXISTS translation_encoding_backup_072 (
    translation_id INT NOT NULL PRIMARY KEY,
    locale VARCHAR(5) NOT NULL,
    category VARCHAR(50) NOT NULL,
    key_name VARCHAR(100) NOT NULL,
    original_translation TEXT NOT NULL,
    original_hex LONGTEXT CHARACTER SET ascii NOT NULL,
    repaired_translation TEXT NOT NULL,
    backed_up_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT IGNORE INTO translation_encoding_backup_072
    (translation_id, locale, category, key_name, original_translation, original_hex, repaired_translation)
SELECT c.id, c.locale, c.category, c.key_name,
       c.original_translation, c.original_hex, c.repaired_translation
FROM (
    SELECT id, locale, category, key_name,
           translation AS original_translation,
           HEX(translation) AS original_hex,
           CONVERT(CAST(CONVERT(translation USING latin1) AS BINARY) USING utf8mb4) AS repaired_translation
    FROM translations
    WHERE
        (locale = 'ru' AND (LOCATE('C390', HEX(translation)) > 0 OR LOCATE('C391', HEX(translation)) > 0))
     OR (locale IN ('de','es','fr') AND (LOCATE('C383', HEX(translation)) > 0 OR LOCATE('C382', HEX(translation)) > 0 OR LOCATE('C3A2E2', HEX(translation)) > 0))
     OR (locale = 'zh' AND HEX(translation) REGEXP 'C3A[4-9]')
     OR (locale = 'en' AND (LOCATE('C3A2E2', HEX(translation)) > 0 OR LOCATE('C3B0C5', HEX(translation)) > 0))
) c
WHERE c.repaired_translation IS NOT NULL
  AND c.repaired_translation NOT LIKE CONCAT('%', CONVERT(0xEFBFBD USING utf8mb4), '%')
  AND HEX(c.original_translation) = HEX(
      CONVERT(CONVERT(CAST(CONVERT(c.repaired_translation USING utf8mb4) AS BINARY) USING latin1) USING utf8mb4)
  );

UPDATE translations t
JOIN translation_encoding_backup_072 b ON b.translation_id = t.id
SET t.translation = b.repaired_translation
WHERE HEX(t.translation) = b.original_hex;

CREATE TABLE IF NOT EXISTS language_encoding_backup_072 (
    language_code VARCHAR(10) NOT NULL PRIMARY KEY,
    original_native_name VARCHAR(100) NOT NULL,
    original_hex VARCHAR(400) CHARACTER SET ascii NOT NULL,
    repaired_native_name VARCHAR(100) NOT NULL,
    backed_up_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

ALTER TABLE language_encoding_backup_072
    MODIFY language_code VARCHAR(10) NOT NULL;

INSERT IGNORE INTO language_encoding_backup_072
    (language_code, original_native_name, original_hex, repaired_native_name)
SELECT c.code, c.original_native_name, c.original_hex, c.repaired_native_name
FROM (
    SELECT code, native_name AS original_native_name, HEX(native_name) AS original_hex,
           CONVERT(CAST(CONVERT(native_name USING latin1) AS BINARY) USING utf8mb4) AS repaired_native_name
    FROM languages
    WHERE LOCATE('C383', HEX(native_name)) > 0
       OR LOCATE('C390', HEX(native_name)) > 0
       OR LOCATE('C391', HEX(native_name)) > 0
       OR HEX(native_name) REGEXP 'C3A[4-9]'
) c
WHERE c.repaired_native_name IS NOT NULL
  AND c.repaired_native_name NOT LIKE CONCAT('%', CONVERT(0xEFBFBD USING utf8mb4), '%')
  AND HEX(c.original_native_name) = HEX(
      CONVERT(CONVERT(CAST(CONVERT(c.repaired_native_name USING utf8mb4) AS BINARY) USING latin1) USING utf8mb4)
  );

UPDATE languages l
JOIN language_encoding_backup_072 b ON b.language_code = l.code
SET l.native_name = b.repaired_native_name
WHERE HEX(l.native_name) = b.original_hex;
