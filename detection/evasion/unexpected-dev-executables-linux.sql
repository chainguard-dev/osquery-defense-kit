-- Find unexpected executables in /dev
--
-- references:
--   * https://www.sandflysecurity.com/blog/bpfdoor-an-evasive-linux-backdoor-technical-analysis/
--
-- tags: persistent state filesystem
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
  (
    -- This list is the result of multiple queries combined and can likely be minimized
    file.path LIKE '/dev/%%'
    OR file.path LIKE '/dev/%%/%%'
    OR file.path LIKE '/dev/mqueue/%%'
    OR file.path LIKE '/dev/mqueue/.%/%%'
    OR file.path LIKE '/dev/mqueue/%/%%'
    OR file.path LIKE '/dev/mqueue/%/%/.%'
    OR file.path LIKE '/dev/mqueue/%/.%/%%'
    OR file.path LIKE '/dev/shm/%%'
    OR file.path LIKE '/dev/shm/.%/%%'
    OR file.path LIKE '/dev/shm/%/%%'
    OR file.path LIKE '/dev/shm/%/%/.%'
    OR file.path LIKE '/dev/shm/%/.%/%%'
  )
  AND file.type = 'regular'
  AND file.size > 64
  AND file.path NOT LIKE '%/../%'
  AND file.path NOT LIKE '%/./%'
  AND (
    file.mode LIKE '%7%'
    or file.mode LIKE '%5%'
    or file.mode LIKE '%1%'
  ) -- Seen on Ubuntu
  AND NOT (
    file.uid = 1000
    AND file.gid = 1000
    AND file.mode = '0700'
    AND (
      magic.data IS NULL
      OR magic.data = 'data'
    )
    AND file.path LIKE '/dev/shm/pulse-shm-%'
    AND file.size > 60000000
  ) -- Seen with Steam
  AND NOT (
    file.uid = 1000
    AND file.gid IN (100, 1000)
    AND file.mode IN ('0755', '0775')
    AND file.path LIKE '/dev/shm/u1000-Shm_%'
    AND (
      magic.data IS NULL
      OR magic.data NOT LIKE "%executable%"
      OR magic.data IN (
        'data',
        'Applesoft BASIC program data, first line number 86',
        'mc68k executable (shared)',
        'DOS executable (COM)'
      )
    )
  )
  AND NOT (
    file.uid = 1000
    AND file.gid IN (100, 1000)
    AND file.mode IN ('0755', '0775')
    AND magic.data IS NULL
    AND file.path LIKE '/dev/shm/u1000-Shm_%'
  )
  AND NOT (
    file.uid = 1000
    AND file.gid IN (100, 1000)
    AND file.mode IN ('0755', '0775')
    AND file.path = '/dev/shm/u1000-ValveIPCSharedObj-Steam'
    AND file.size > 2000000
  )
  AND NOT (
    file.uid = 1000
    AND file.mode = '0755'
    AND file.path LIKE '/dev/shm/flatpak-com.valvesoftware.Steam-%/u1000-Shm_%'
    AND file.size > 1000000
  )
