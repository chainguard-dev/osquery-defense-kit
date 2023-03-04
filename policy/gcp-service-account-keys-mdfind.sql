-- Indicative of stored GCP service account keys just sitting around unencrypted
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
  LEFT JOIN file ON mdfind.path = file.path
  LEFT JOIN users u ON file.uid = u.uid
  LEFT JOIN hash ON mdfind.path = hash.path
  LEFT JOIN extended_attributes ea ON mdfind.path = ea.path
  AND ea.key = 'where_from'
  LEFT JOIN magic ON mdfind.path = magic.path
  LEFT JOIN signature ON mdfind.path = signature.path
WHERE
  mdfind.query = "kMDItemFSName == '*.json'"
  AND file.filename LIKE "%-%-%.json"
  AND file.size BETWEEN 2311 AND 2385 -- Don't alert on tokens that begin with the username-, as they may be personal
  AND NOT INSTR(file.filename, CONCAT (u.username, "-")) == 1 -- Don't alert on tokens that begin with the users full name and a dash
  AND NOT INSTR(
    file.filename,
    REPLACE(LOWER(TRIM(u.description)), " ", "-")
  ) == 1 -- Common locations of test or demo keys
  AND NOT file.directory LIKE '%/go/pkg/%'
  AND NOT file.directory LIKE '%/go/src/%'
  AND NOT file.directory LIKE '%/aws-sdk/apis'
  AND NOT file.directory LIKE '%/mock-infras/%'
  AND NOT file.directory LIKE '%/testdata/%'
  AND NOT file.directory LIKE '%/schemas'
  AND NOT file.directory LIKE '/Users/%/Library/Application Support/%'
  AND NOT file.directory LIKE '%demo' -- Common filenames that are non-controversial
  AND NOT file.filename IN (
    'service-account-file.json',
    'redshift-2012-12-01.waiters2.json',
    'organizations-2016-11-28.paginators.json'
  )
GROUP BY
  file.path
