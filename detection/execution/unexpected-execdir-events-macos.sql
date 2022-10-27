-- Catch applications running from unusual directories, such as /tmp
--
-- references:
--   * https://attack.mitre.org/techniques/T1074/
--
-- false positives:
--   * software installers and updaters
--   * developers running programs out of /tmp
--
-- interval: 60
-- platform: darwin
-- tags: filesystem events
SELECT
  p.pid,
  p.path,
  REGEX_MATCH (p.path, '(.*)/', 1) AS dirname,
  REPLACE(file.directory, u.directory, '~') AS homedir,
  p.cmdline,
  p.mode,
  p.cwd,
  p.euid,
  p.parent,
  pp.path AS parent_path,
  pp.name AS parent_name,
  pp.cmdline AS parent_cmd,
  pp.euid AS parent_euid,
  hash.sha256 AS parent_sha256
FROM
  process_events p
  LEFT JOIN processes ON p.pid = processes.pid
  LEFT JOIN file ON p.path = file.path
  LEFT JOIN users u ON p.uid = u.uid
  LEFT JOIN processes pp ON p.parent = pp.pid
  LEFT JOIN hash ON pp.path = hash.path
WHERE
  p.time > (strftime('%s', 'now') -60)
  -- The process_events table on macOS ends up with relative directories for some reason?
  AND dirname LIKE '/%'
  AND file.size > 0
  AND dirname NOT IN (
    '/bin',
    '/Library/DropboxHelperTools/Dropbox_u501',
    '/Library/Google/GoogleSoftwareUpdate/GoogleSoftwareUpdate.bundle/Contents/Helpers/GoogleSoftwareUpdateAgent.app/Contents/MacOS',
    '/Library/Google/GoogleSoftwareUpdate/GoogleSoftwareUpdate.bundle/Contents/Helpers.app/Contents/MacOS',
    '/Library/Printers/DYMO/Utilities',
    '/Library/Application Support/Logitech.localized/Logitech Options.localized/LogiMgrUpdater.app/Contents/Resources',
    '/usr/lib/system',
    '/Library/PrivilegedHelperTools',
    '/sbin',
    '/nix/store',
    '/usr/bin',
    '/usr/lib',
    '/Library/TeX/texbin',
    '/usr/lib/bluetooth',
    '/usr/lib/cups/notifier',
    '/Library/Frameworks/Python.framework/Versions/3.10/bin',
    '/usr/libexec',
    '/usr/libexec/ApplicationFirewall',
    '/usr/libexec/rosetta',
    '/node_modules/.bin',
    '/nix/var/nix/profiles/default/bin',
    '/run/current-system/sw/bin',
    '/usr/libexec/firmwarecheckers/eficheck',
    '/usr/sbin',
    '/usr/share/code'
  )
  AND dirname NOT LIKE '/Applications/%.app/%'
  AND dirname NOT LIKE '/etc/profiles/per-user/%/bin'
  AND dirname NOT LIKE '/home/%'
  AND dirname NOT LIKE '/Library/%/%.bundle/Contents/Helpers'
  AND dirname NOT LIKE '/Library/%/Resources/%/Contents/MacOS'
  AND dirname NOT LIKE '/Library/%/sbin' -- Nessus
  AND dirname NOT LIKE '/Library/Apple/System/%'
  AND dirname NOT LIKE '/Library/Application Support/%/Contents/MacOS'
  AND dirname NOT LIKE '/Library/Application Support/Adobe/%'
  AND dirname NOT LIKE '/Library/Audio/Plug-Ins/%/Contents/MacOS'
  AND dirname NOT LIKE '/Library/CoreMediaIO/Plug-Ins/%'
  AND dirname NOT LIKE '/Library/Developer/%'
  AND dirname NOT LIKE '/Library/Developer/CommandLineTools/Library/%'
  AND dirname NOT LIKE '/Library/Internet Plug-Ins/%/Contents/MacOS'
  AND dirname NOT LIKE '/Library/Java/JavaVirtualMachines/%'
  AND dirname NOT LIKE '/Library/SystemExtensions/%'
  AND dirname NOT LIKE '/nix/store/%'
  AND dirname NOT LIKE '/opt/%'
  AND dirname NOT LIKE '/private/tmp/go-build%/exe'
  AND dirname NOT LIKE '/private/tmp/nix-build-%'
  AND dirname NOT LIKE '/private/var/db/com.apple.xpc.roleaccountd.staging/%.xpc/Contents/MacOS'
  AND dirname NOT LIKE '/private/var/folders/%/bin'
  AND dirname NOT LIKE '/private/var/folders/%/Contents/%'
  AND dirname NOT LIKE '/private/var/folders/%/go-build%'
  AND dirname NOT LIKE '/private/var/folders/%/GoLand'
  AND dirname NOT LIKE '/snap/%'
  AND dirname NOT LIKE '/store/%/bin'
  AND dirname NOT LIKE '/System/%'
  AND dirname NOT LIKE '/Users/%'
  AND dirname NOT LIKE '/usr/libexec/%'
  AND dirname NOT LIKE '/usr/local/%'
  AND dirname NOT LIKE '/Volumes/com.getdropbox.dropbox-%'
  AND dirname NOT LIKE '/private/tmp/KSInstallAction.%/Install Google Software Update.app/Contents/Helpers'
  -- Unexplained data issue
  AND dirname NOT LIKE '../%'
  AND p.path NOT IN (
    '/Applications/Stats.app/Contents/MacOS/Stats',
    '/usr/libexec/AssetCache/AssetCache',
    '_build/krew/bin/git',
    '/Library/PrivilegedHelperTools/com.adobe.acc.installer.v2',
    '/Library/DropboxHelperTools/DropboxHelperInstaller',
    '/Library/PrivilegedHelperTools/com.adobe.ARMDC.Communicator',
    '/Library/PrivilegedHelperTools/com.adobe.ARMDC.SMJobBlessHelper',
    '/Library/PrivilegedHelperTools/com.docker.vmnetd',
    '/Library/PrivilegedHelperTools/com.macpaw.CleanMyMac4.Agent',
    '/Library/PrivilegedHelperTools/keybase.Helper'
  )
  -- Nix
  AND parent_path NOT LIKE '/nix/store/%'
  -- Homebrew and other compilations
  AND parent_cmd NOT LIKE '%./configure%'
  -- Pulumi executables are often executed from $TMPDIR
  AND NOT (
    dirname LIKE '/private/var/%'
    AND processes.name LIKE 'pulumi-go.%'
  )
  -- Chrome executes patches from /tmp :(
  AND NOT (
    dirname LIKE '/private/tmp/%'
    AND processes.name = 'goobspatch'
  )
  -- Don't spam alerts with repeated invocations of the same command-line
GROUP BY
  p.cmdline,
  p.cwd,
  p.euid
