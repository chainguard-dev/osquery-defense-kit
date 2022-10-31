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
  -- It's pretty rare, but some vendors install updates into /var. Spotify, I'm looking at you!
  AND NOT signature.authority IN (
    'Developer ID Application: Spotify (2FNC3A47ZF)',
    'Developer ID Application: Adobe Inc. (JQ525L2MZD)',
    'Developer ID Application: Docker Inc (9BNSXJN65R)',
    'Developer ID Application: GitHub (VEKTX9H2N7)',
    'Developer ID Application: Google LLC (EQHXZ8M8AV)',
    'Developer ID Application: Microsoft Corporation (UBF8T346G9)',
    'Developer ID Application: Mozilla Corporation (43AQ936H96)'
  )
  AND file.path NOT IN (
    '/var/log/acroUpdaterTools.log',
    '/var/vm/sleepimage'
  )
  AND file.size > 10
  AND NOT (
    file.path LIKE '/var/folders/%/T/sp_update/%'
    AND file.gid = 20
    AND file.uid = 501
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