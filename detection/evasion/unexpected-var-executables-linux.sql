-- Find unexpected executables in /var
SELECT
  file.path,
  file.directory,
  uid,
  gid,
  mode,
  file.mtime,
  file.size,
  hash.sha256,
  magic.data
FROM
  file
  LEFT JOIN hash on file.path = hash.path
  LEFT JOIN magic ON file.path = magic.path
WHERE
  (file.path LIKE "/var/%%")
  AND file.type = "regular"
  AND (
    file.mode LIKE "%7%"
    or file.mode LIKE "%5%"
    or file.mode LIKE "%1%"
  )
  AND file.directory NOT IN (
    "/var/lib/colord",
    "/var/ossec/agentless",
    "/var/ossec/bin",
    "/var/ossec/wodles",
    "/var/run/booted-system",
    "/var/run/current-system"
  )
