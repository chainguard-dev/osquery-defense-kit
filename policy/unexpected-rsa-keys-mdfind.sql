-- Indicative of stored RSA keys just sitting around unencrypted
--
-- tags: persistent state filesystem
-- platform: darwin
SELECT
  file.path,
  file.size,
  datetime(file.btime, 'unixepoch') AS file_created,
  magic.data,
  hash.sha256,
  ea.value AS url
FROM
  mdfind
  JOIN file ON mdfind.path = file.path
  JOIN users u ON file.uid = u.uid
  LEFT JOIN hash ON mdfind.path = hash.path
  LEFT JOIN extended_attributes ea ON mdfind.path = ea.path
  AND ea.key = 'where_from'
  LEFT JOIN magic ON mdfind.path = magic.path
  LEFT JOIN signature ON mdfind.path = signature.path
WHERE
  mdfind.query = "kMDItemFSName == '*.rsa'"
  AND file.filename NOT IN ('local-melange.rsa', 'melange.rsa')
  AND size BETWEEN 128 AND 8192
  -- Don't alert on tokens that begin with the username-, as they may be personal
  AND NOT INSTR(filename, CONCAT (u.username, "-")) == 1
  -- Don't alert on tokens that begin with the users full name and a dash
  AND NOT INSTR(
    filename,
    REPLACE(LOWER(TRIM(description)), " ", "-")
  ) == 1
  -- Common filenames that are non-controversial
  AND NOT file.filename LIKE '%example.com%'
  AND NOT file.path LIKE "%/testdata/%"
GROUP BY
  file.path
