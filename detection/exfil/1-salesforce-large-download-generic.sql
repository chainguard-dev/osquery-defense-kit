-- Returns a list of files likely exported from Salesforce
--
-- platform: posix
-- tags: persistent filesystem often
SELECT
  file.path,
  file.size,
  datetime(file.btime, 'unixepoch') AS file_created,
  datetime(file.atime, 'unixepoch') AS file_accessed,
  hash.sha256
FROM
  file
  LEFT JOIN hash ON file.path = hash.path
WHERE
  (
    file.path LIKE '/Users/%/Downloads/%-202%-%-%-%-%-%.xlsx'
    OR file.path LIKE '/home/%/Downloads/%-202%-%-%-%-%-%.xlsx'
    OR file.path LIKE '/Users/%/Downloads/WE_%.ZIP'
    OR file.path LIKE '/home/%/Downloads/WE_%.ZIP'
    OR file.path LIKE '/Users/%/Downloads/report17%.%'
    OR file.path LIKE '/home/%/Downloads/report17%.%'
    OR file.path LIKE '/Users/%/Downloads/%/Cont%act.csv'
    OR file.path LIKE '/home/%/Downloads/%/Cont%act.csv'
  )
  AND file.btime > (strftime('%s', 'now') -86400)
  AND file.size > 500000
GROUP BY
  file.path
