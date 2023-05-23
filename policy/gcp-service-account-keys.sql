-- Indicative of stored GCP service account keys just sitting around unencrypted
--
-- tags: persistent state filesystem
-- platform: posix
SELECT
  file.path,
  file.filename,
  file.type,
  file.size,
  file.mtime,
  file.uid,
  file.ctime,
  file.gid,
  hash.sha256,
  magic.data
FROM
  file
  LEFT JOIN hash ON file.path = hash.path
  LEFT JOIN users u ON file.uid = u.uid
  LEFT JOIN magic ON file.path = magic.path
WHERE
  (
    file.directory LIKE '/Users/%/Downloads/%'
    OR file.directory LIKE '/home/%/%'
    OR file.directory LIKE '/home/%/'
    OR file.directory LIKE '/home/%/.%'
    OR file.directory LIKE '/home/%/Downloads/%'
    OR file.directory LIKE '/tmp/%'
    OR file.directory LIKE '/tmp/'
    OR file.directory LIKE '/Users/%/%'
    OR file.directory LIKE '/Users/%/'
    OR file.directory LIKE '/Users/%/.%'
    OR file.directory LIKE '/var/tmp/%'
    OR file.directory LIKE '/var/tmp/'
  )
  AND file.directory NOT LIKE "%/../%"
  AND file.directory NOT LIKE "%/./%"
  AND filename LIKE "%-%-%.json"
  AND size BETWEEN 2311 AND 2385
  -- Don't alert on tokens that begin with the username-, as they may be personal
  AND NOT INSTR(filename, CONCAT (u.username, "-")) == 1
  -- Don't alert on tokens that begin with the users full name and a dash
  AND NOT INSTR(
    filename,
    REPLACE(LOWER(TRIM(description)), " ", "-")
  ) == 1
  -- Demo keys
  AND NOT file.filename LIKE 'host-project-%'
  AND NOT file.filename LIKE 'ulabs-%'
  AND NOT hash.sha256 IN (
    "c7d6bac8e942511e25973889ac38656d4d46f68044650d694721017fda23716e",
    "bd5f4c01ebb5636b94584ee4ae42514b27d371859f7344f6aa5a37332ee714ba"
  )
