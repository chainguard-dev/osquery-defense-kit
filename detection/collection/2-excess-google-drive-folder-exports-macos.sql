-- Surface when a machine has downloaded an unusual number of zip exports from Google Drive
--
-- platform: darwin
-- tags: persistent filesystem spotlight
-- interval: 3600
SELECT
  COUNT(DISTINCT file.path) AS num_exports,
  GROUP_CONCAT(DISTINCT file.path) AS paths,
  SUM(file.size) AS total_size,
  MIN(file.btime) AS first_btime,
  MAX(file.atime) AS last_atime
FROM
  mdfind
  JOIN file ON mdfind.path = file.path
  JOIN hash ON file.path = hash.path
  JOIN extended_attributes ea ON mdfind.path = ea.path
WHERE
  mdfind.query = "kMDItemWhereFroms == 'https://*-drive-data-export.googleusercontent.com*' AND 'kMDItemFSCreationDate >= $time.now(-604800)'"
  -- this seems excessive, but I was having issues with kMDItemFSCreationDate not filtering appropriately
  AND MAX(file.btime, file.ctime, file.mtime) > (strftime('%s', 'now') -604800)
  -- "GROUP BY" should be unnecessary, but Kolide seems to require it
GROUP BY
  ea.key
HAVING
  total_size > (100 * 1024 * 1024)
  OR num_exports > 1
ORDER BY
  file.path ASC
