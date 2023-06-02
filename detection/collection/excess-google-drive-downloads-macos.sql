-- Surface when a machine has downloaded an unusual number of files from Google Drive
--
-- platform: darwin
-- tags: persistent filesystem spotlight
-- interval: 3600
SELECT
  COUNT(DISTINCT file.path) AS num_downloads,
  GROUP_CONCAT(DISTINCT file.path) AS paths,
  SUM(file.size) AS total_size,
  MIN(file.btime) AS first_btime,
  MAX(file.atime) AS last_atime
FROM
  mdfind
  JOIN file ON mdfind.path = file.path
  JOIN extended_attributes ea ON mdfind.path = ea.path
  AND ea.key = "where_from"
WHERE
  query = "kMDItemFSCreationDate >= $time.now(-604800)"
  -- For some reason relying on kMDItemWhereFroms omitted download word docs, so
  -- this does it the slow way.
  AND ea.value LIKE "https://doc-%googleusercontent.com%"
 -- this seems excessive, but I was having issues with kMDItemFSCreationDate not filtering appropriately
  AND MAX(file.btime, file.ctime, file.mtime) > (strftime('%s', 'now') -604800) 
-- "GROUP BY" should be unnecessary, but Kolide seems to require it
GROUP BY ea.key
HAVING total_size > (100*1024*1024) OR num_downloads > 4