-- Indicative of stored RSA keys just sitting around unencrypted
--
-- tags: persistent state filesystem seldom
-- platform: posix
SELECT
  file.path,
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
  AND filename LIKE "%.rsa"
  AND size BETWEEN 128 AND 8192
  -- Don't alert on tokens that begin with the username-, as they may be personal
  AND NOT INSTR(filename, CONCAT (u.username, "-")) == 1
  -- Don't alert on tokens that begin with the users full name and a dash
  AND NOT INSTR(
    filename,
    REPLACE(LOWER(TRIM(description)), " ", "-")
  ) == 1
  -- Common filenames that are non-controversial
  AND NOT INSTR(file.filename, 'melange.rsa') > 0
  -- Demo keys
  AND NOT sha256 IN ('a68b29401730a9c5f3e06099f6703a43797ee5c6ad6c741961c6eb8ab39786de')
