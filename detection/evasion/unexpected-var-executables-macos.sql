-- Find unexpected executables in /var
--
-- false positives:
--   * none known
--
-- tags: persistent
-- platform: darwin
SELECT
  file.path,
  file.directory,
  uid,
  gid,
  mode,
  file.mtime,
  file.size,
  hash.sha256,
  magic.data,
  signature.authority,
  signature.identifier
FROM
  file
  LEFT JOIN hash on file.path = hash.path
  LEFT JOIN magic ON file.path = magic.path
  LEFT JOIN signature ON file.path = signature.path
WHERE
  (
    -- This list is the result of multiple queries combined and can likely be minimized
    file.path LIKE '/var/%%'
    OR file.path LIKE '/var/tmp/%%'
    OR file.path LIKE '/var/tmp/.%/%%'
    OR file.path LIKE '/var/tmp/%/%%'
    OR file.path LIKE '/var/tmp/%/%/.%'
    OR file.path LIKE '/var/tmp/%/.%/%%'
    OR file.path LIKE '/var/spool/%%'
    OR file.path LIKE '/var/spool/.%/%%'
    OR file.path LIKE '/var/spool/%/%%'
    OR file.path LIKE '/var/spool/%/%/.%'
    OR file.path LIKE '/var/spool/%/.%/%%'
  )
  AND file.type = 'regular'
  AND file.path NOT LIKE '%/../%'
  AND file.path NOT LIKE '%/./%'
  -- Rosetta cache, SIP protected
  AND file.path NOT LIKE '/var/db/oah/%'
  AND file.path NOT LIKE '/var/folders/%/C/com.apple.FontRegistry/annex_aux'
  AND file.path NOT LIKE '/var/folders/%/T/go.%.%.sum'
  AND file.path NOT LIKE '/var/folders%/T/sp_relauncher'
  AND file.path NOT LIKE '/var/tmp/epdfinfo%'
  AND file.path NOT LIKE '/var/folders/%/T/jansi-%-libjansi.jnilib'
  AND file.path NOT LIKE '/var/tmp/IN_PROGRESS_sysdiagnose_%.tmp/mddiagnose.mdsdiagnostic/diagnostic.log'
  AND (
    file.mode LIKE '%7%'
    or file.mode LIKE '%5%'
    or file.mode LIKE '%1%'
  )
  AND file.directory NOT IN (
    '/var/ossec/agentless',
    '/var/ossec/bin',
    '/var/ossec/wodles',
    '/var/run/booted-system',
    '/var/run/current-system',
    '/var/run/current-system/sw/bin',
    '/var/select',
    '/var/db/xcode_select_link/usr/bin',
    '/var/db/xcode_select_link/usr/lib',
    '/var/db/xcode_select_link/usr/libexec',
    '/var/select/X11/bin',
    '/var/select/X11/lib/dri',
    '/var/select/X11/lib/flat_namespace',
    '/var/select/X11/lib',
    '/var/select/X11/libexec'
  )
  AND file.path NOT IN (
    '/var/log/acroUpdaterTools.log',
    '/var/vm/sleepimage'
  )
  AND file.size > 10
  AND hash.sha256 NOT IN (
    'fd53abe096b3617c32d46db34fad58770f697a3bf4aef3d8861f37d8471f6c98', -- sp_relauncher (Spotify)
    '65afd3fad04973e83d3cd3be56a310d11ed2c096319f1e2b20c4d153446f1b9f' -- sp_relauncher (Spotify)
  )
  AND NOT (
    file.path LIKE '/var/db/timezone/zoneinfo/%/%'
    AND magic.data LIKE 'timezone%'
    AND file.size < 3000
    AND file.mode = 0755
  )
  -- JetBrains (Delve)
  AND NOT (
    file.path LIKE '/var/folders/%/T/dlvLauncher.sh'
    AND magic.data LIKE 'Bourne-Again shell script%'
    AND file.size < 1024
    AND file.mode = 0744
  )