-- Surface Salesforce exports (possible data exfiltration)
--
-- platform: darwin
-- tags: persistent filesystem spotlight often
SELECT
  file.path,
  file.size,
  datetime(file.btime, 'unixepoch') AS file_created,
  datetime(file.atime, 'unixepoch') AS file_accessed,
  hash.sha256,
  ea.value
FROM
  mdfind
  LEFT JOIN file ON mdfind.path = file.path
  LEFT JOIN hash ON file.path = hash.path
  LEFT JOIN extended_attributes ea ON mdfind.path = ea.path
WHERE
  mdfind.query = 'kMDItemWhereFroms == ''*https://*.my.salesforce.com/*'''
  AND ea.key = 'where_from'
  AND file.size > 500000
GROUP BY
  file.path
