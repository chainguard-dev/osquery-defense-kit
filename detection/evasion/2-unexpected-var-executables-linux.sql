-- Find unexpected executables in /var
--
-- false positives:
--   * none known
--
-- tags: persistent
-- platform: linux
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
    file.path LIKE '/var/%%'
    OR file.path LIKE '/var/spool/.%/%%'
    OR file.path LIKE '/var/spool/%/.%/%%'
    OR file.path LIKE '/var/spool/%/%/.%'
    OR file.path LIKE '/var/spool/%/%%'
    OR file.path LIKE '/var/spool/%%'
    OR file.path LIKE '/var/tmp/.%/%%'
    OR file.path LIKE '/var/tmp/%/.%/%%'
    OR file.path LIKE '/var/tmp/%/%/.%'
    OR file.path LIKE '/var/tmp/%/%%'
    OR file.path LIKE '/var/tmp/%%'
  )
  AND file.type = 'regular'
  AND file.path NOT LIKE '/var/tmp/buildah-cache-1000/var/cache/rpm-ostree/%'
  AND file.path NOT LIKE '/var/tmp/images/%'
  AND file.path NOT LIKE '/var/tmp/packages/%'
  AND file.path NOT LIKE '%/../%'
  AND file.path NOT LIKE '%/./%'
  AND file.directory NOT LIKE '/var/tmp/buildah%/run'
  AND (
    file.mode LIKE '%7%'
    OR file.mode LIKE '%5%'
    OR file.mode LIKE '%1%'
  )
  AND file.directory NOT IN (
    '/var/lib/colord',
    '/var/ossec/agentless',
    '/var/ossec/bin',
    '/var/ossec/wodles',
    '/var/run/booted-system',
    '/var/run/current-system',
    '/var/usrlocal/bin',
    '/var/usrlocal/lib64',
    '/var/vanta'
  )
  AND file.directory NOT LIKE '/var/tmp/ostree-unlock-ovl.%/upper/bin'
  AND file.path NOT IN (
    '/var/run/lima-boot-done',
    '/var/run/lima-ssh-ready',
    '/var/opt/bin/elastic-agent'
  )
  AND NOT (
    file.directory = '/var/spool/postfix/incoming'
    AND size < 1024
    AND mode = '07000'
    AND gid = 0
  )
  AND (
    magic.data IS NULL
    OR magic.data != 'JSON data'
  )
  AND file.size > 10
