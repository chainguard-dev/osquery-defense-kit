-- Find unexpected executables in /var
--
-- false positives:
--   * none known
--
-- tags: persistent seldom
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
WHERE -- Optimization: don't join things until we have a whittled down list of files
  file.path IN (
    SELECT DISTINCT
      path
    FROM
      file
    WHERE
      (
        file.directory = '/var/tmp'
        OR file.directory LIKE '/var/tmp/%'
        OR file.directory LIKE '/var/tmp/%/%'
        OR file.directory LIKE '/var/tmp/%/.%'
        OR file.directory LIKE '/var/tmp/.%'
        OR file.directory LIKE '/var/tmp/.%/%'
        or file.directory LIKE '/var/tmp/.%/.%'
        OR file.directory = '/var/spool'
        OR file.directory LIKE '/var/spool/%'
        OR file.directory LIKE '/var/spool/%/%'
        OR file.directory LIKE '/var/spool/%/.%'
        OR file.directory LIKE '/var/spool/.%'
        OR file.directory LIKE '/var/spool/.%/%'
        or file.directory LIKE '/var/spool/.%/.%'
      ) -- Prevent weird recursion
      AND NOT file.directory LIKE '%/../%'
      AND NOT file.directory LIKE '%/./%' -- Exclude very temporary files
      AND NOT (strftime('%s', 'now') - ctime) < 60 -- Only executable files
      AND file.type = 'regular'
      AND (
        file.mode LIKE '%7%'
        or file.mode LIKE '%5%'
        or file.mode LIKE '%1%'
      ) -- Rosetta cache, SIP protected
      AND file.path NOT LIKE '/var/db/oah/%'
      AND file.path NOT LIKE '/var/folders/%/C/com.apple.FontRegistry/annex_aux'
      AND file.path NOT LIKE '/var/folders/%/T/go.%.%.sum'
      AND file.path NOT LIKE '/var/folders/%/T/pulumi-go.%'
      AND file.path NOT LIKE '/var/folders/%/T/sp_relauncher'
      AND file.path NOT LIKE '/var/folders/%/T/iTerm2-script%'
      AND file.path NOT LIKE '/var/tmp/epdfinfo%'
      AND file.path NOT LIKE '/var/folders/%/T/jansi-%-libjansi.jnilib'
      AND file.path NOT LIKE '/var/tmp/IN_PROGRESS_sysdiagnose_%.tmp/mddiagnose.mdsdiagnostic/diagnostic.log'
      AND file.path NOT LIKE '/var/run/current-system/etc/profiles/per-user/%'
      AND file.path NOT LIKE '/var/folders/%/T/freefn-%_emacs_%.eln'
      AND file.directory NOT IN (
        '/var/db/xcode_select_link/Makefiles/VersioningSystems/',
        '/var/db/xcode_select_link/usr/bin',
        '/var/db/xcode_select_link/usr/lib',
        '/var/db/xcode_select_link/usr/libexec',
        '/var/ossec/agentless',
        '/var/ossec/bin',
        '/var/ossec/wodles',
        '/var/run/booted-system',
        '/var/run/current-system',
        '/var/run/current-system/sw/bin',
        '/var/select',
        '/var/select/X11/bin',
        '/var/select/X11/lib',
        '/var/select/X11/lib/dri',
        '/var/select/X11/libexec',
        '/var/select/X11/lib/flat_namespace'
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
      ) -- JetBrains (Delve)
      AND NOT (
        file.path LIKE '/var/folders/%/T/dlvLauncher%.sh'
        AND file.size < 1024
        AND file.mode = '0744'
      )
      AND NOT (
        file.path LIKE '/var/folders/%/T/libjansi-%.jnilib'
        AND file.size < 40000
        AND file.uid = 501
      )
      AND NOT (
        file.path LIKE '/var/tmp/_bazel_%/%/install/%'
        AND file.uid = 501
      )
  ) -- It's pretty rare, but some vendors install updates into /var. Spotify, I'm looking at you!
  AND NOT signature.authority IN (
    'Developer ID Application: Adobe Inc. (JQ525L2MZD)',
    'Developer ID Application: Docker Inc (9BNSXJN65R)',
    'Developer ID Application: GitHub (VEKTX9H2N7)',
    'Developer ID Application: Google LLC (EQHXZ8M8AV)',
    'Developer ID Application: Microsoft Corporation (UBF8T346G9)',
    'Developer ID Application: Mozilla Corporation (43AQ936H96)',
    'Developer ID Application: Spotify (2FNC3A47ZF)',
    'Software Signing'
  )
  AND NOT (
    file.path LIKE '/var/db/timezone/zoneinfo/%'
    AND magic.data LIKE 'timezone%'
    AND file.size < 3000
    AND file.mode = '0755'
  ) -- Epson
  AND NOT (
    file.path LIKE '/var/tmp/InstallLog/%.plist'
    AND magic.data = 'Apple binary property list'
    AND file.size < 3000
    AND file.mode = '0777'
  )
GROUP BY
  file.path
