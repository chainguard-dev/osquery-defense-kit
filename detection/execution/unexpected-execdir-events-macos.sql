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
  REGEX_MATCH (p.path, '(.*)/', 1) AS dir,
  REGEX_MATCH (p.path, '(/.*?/.*?/.*?)/', 1) AS top_dir, -- 3 levels deep
  REPLACE(file.directory, u.directory, '~') AS homedir,
  REGEX_MATCH (
    REPLACE(file.directory, u.directory, '~'),
    '(~/.*?/)',
    1
  ) AS top_homedir, -- 1 level deep
  p.cmdline,
  p.mode,
  p.cwd,
  p.euid,
  p.parent,
  pp.path AS parent_path,
  pp.name AS parent_name,
  pp.cmdline AS parent_cmd,
  pp.euid AS parent_euid,
  hash.sha256 AS child_sha256,
  phash.sha256 AS parent_sha256,
  signature.identifier,
  signature.authority
FROM
  process_events p
  LEFT JOIN processes ON p.pid = processes.pid
  LEFT JOIN file ON p.path = file.path
  LEFT JOIN users u ON p.uid = u.uid
  LEFT JOIN processes pp ON p.parent = pp.pid
  LEFT JOIN hash ON p.path = hash.path
  LEFT JOIN hash phash ON pp.path = phash.path
  LEFT JOIN signature ON p.path = signature.path
WHERE
  p.time > (strftime('%s', 'now') -60)
  -- The process_events table on macOS ends up with relative directories for some reason?
  AND dir LIKE '/%'
  AND file.size > 0
  AND dir NOT IN (
    '/bin',
    '/Library/Application Support/Logitech.localized/Logitech Options.localized/LogiMgrUpdater.app/Contents/Resources',
    '/Library/DropboxHelperTools/Dropbox_u501',
    '/Library/Filesystems/kbfuse.fs/Contents/Resources',
    '/Library/Frameworks/Python.framework/Versions/3.10/bin',
    '/Library/Google/GoogleSoftwareUpdate/GoogleSoftwareUpdate.bundle/Contents/Helpers.app/Contents/MacOS',
    '/Library/Google/GoogleSoftwareUpdate/GoogleSoftwareUpdate.bundle/Contents/Helpers/GoogleSoftwareUpdateAgent.app/Contents/MacOS',
    '/Library/Printers/DYMO/Utilities',
    '/Library/PrivilegedHelperTools',
    '/Library/TeX/texbin',
    '/nix/store',
    '/nix/var/nix/profiles/default/bin',
    '/node_modules/.bin',
    '/opt/homebrew/Caskroom/google-cloud-sdk/latest/google-cloud-sdk/bin/gke-gcloud-auth-plugin',
    '/opt/usr/bin',
    '/opt/X11/bin',
    '/opt/X11/libexec',
    '/run/current-system/sw/bin',
    '/sbin',
    '/usr/bin',
    '/usr/lib',
    '/usr/lib/bluetooth',
    '/usr/lib/cups/notifier',
    '/usr/libexec',
    '/usr/libexec/ApplicationFirewall',
    '/usr/libexec/AssetCache',
    '/usr/libexec/firmwarecheckers',
    '/usr/libexec/firmwarecheckers/eficheck',
    '/usr/libexec/rosetta',
    '/usr/lib/fwupd',
    '/usr/lib/ibus',
    '/usr/lib/system',
    '/usr/local/bin',
    '/usr/sbin'
  )
  AND top_dir NOT IN (
    '/Applications/Firefox.app/Contents',
    '/Applications/Google Chrome.app/Contents',
    '/Library/Apple/System',
    '/Library/Application Support/Adobe',
    '/Library/Application Support/GPGTools',
    '/Library/Google/GoogleSoftwareUpdate',
    '/System/Applications/Mail.app',
    '/System/Applications/Music.app',
    '/System/Applications/News.app',
    '/System/Applications/TV.app',
    '/System/Applications/Weather.app',
    '/System/Library/CoreServices',
    '/System/Library/Filesystems',
    '/System/Library/Frameworks',
    '/System/Library/PrivateFrameworks',
    '/System/Library/SystemConfiguration',
    '/System/Library/SystemProfiler',
    '/System/Volumes/Preboot',
    '/usr/local/kolide-k2'
  )
  AND homedir NOT IN (
    '~/bin',
    '~/code/bin',
    '~/.magefile',
    '~/go/bin',
    '~/.local/bin',
    '~/projects/go/bin'
  )
  AND top_homedir NOT IN (
    '~/Applications/',
    '~/bin/',
    '~/.cargo/',
    '~/code/',
    '~/.config/',
    '~/go/',
    '~/homebrew/',
    '~/Library/',
    '~/.local/',
    '~/projects/',
    '~/.pyenv/',
    '~/src/',
    '~/.tflint.d/',
    '~/.vscode/',
    '~/.vs-kubernetes/'
  )
  -- Locally built executables
  AND NOT (
    signature.identifier = "a.out"
    AND homedir LIKE '~/%'
    AND pp.name IN ('fish', 'sh', 'bash', 'zsh', 'terraform', 'code')
  )
  AND dir NOT LIKE '../%' -- data issue
  AND dir NOT LIKE '/Applications/%'
  AND dir NOT LIKE '/private/tmp/%.app/Contents/MacOS'
  AND dir NOT LIKE '/private/tmp/go-build%/exe'
  AND dir NOT LIKE '/private/tmp/KSInstallAction.%/Install Google Software Update.app/Contents/Helpers'
  AND dir NOT LIKE '/private/tmp/nix-build-%'
  AND dir NOT LIKE '/private/tmp/PKInstallSandbox.%/Scripts/com.microsoft.OneDrive.%'
  AND dir NOT LIKE '/private/var/db/com.apple.xpc.roleaccountd.staging/%.xpc/Contents/MacOS'
  AND dir NOT LIKE '/private/var/folders/%/bin'
  AND dir NOT LIKE '%/.terraform/providers/%'
  AND dir NOT LIKE '/private/var/folders/%/Contents/%'
  AND dir NOT LIKE '/private/var/folders/%/d/Wrapper/%.app'
  AND dir NOT LIKE '/private/var/folders/%/go-build%'
  AND dir NOT LIKE '/private/var/folders/%/GoLand'
  AND dir NOT LIKE '/Volumes/com.getdropbox.dropbox-%'
  AND homedir NOT LIKE '~/Library/Caches/ms-playwright/%'
  AND homedir NOT LIKE '~/%/node_modules/.pnpm/esbuild-%/node_modules/esbuild-darwin-arm64/bin'
  AND signature.authority NOT IN (
    'Apple iPhone OS Application Signing',
    'Apple Mac OS Application Signing',
    'Developer ID Application: Adobe Inc. (JQ525L2MZD)',
    'Developer ID Application: Cisco (DE8Y96K9QP)',
    'Developer ID Application: CodeWeavers Inc. (9C6B7X7Z8E)',
    'Developer ID Application: Corsair Memory, Inc. (Y93VXCB8Q5)',
    'Developer ID Application: Docker Inc (9BNSXJN65R)',
    'Developer ID Application: Dropbox, Inc. (G7HH3F8CAK)',
    'Developer ID Application: Figma, Inc. (T8RA8NE3B7)',
    'Developer ID Application: GEORGE NACHMAN (H7V7XYVQ7D)',
    'Developer ID Application: Google LLC (EQHXZ8M8AV)',
    'Developer ID Application: Hashicorp, Inc. (D38WU7D763)',
    'Developer ID Application: Logitech Inc. (QED4VVPZWA)',
    'Developer ID Application: Microsoft Corporation (UBF8T346G9)',
    'Developer ID Application: Ned Deily (DJ3H93M7VJ)', -- Python
    'Developer ID Application: Node.js Foundation (HX7739G8FX)',
    'Developer ID Application: Objective Development Software GmbH (MLZF7K7B5R)',
    'Developer ID Application: Objective-See, LLC (VBG97UB4TA)',
    'Developer ID Application: Opal Camera Inc (97Z3HJWCRT)',
    'Developer ID Application: Oracle America, Inc. (VB5E2TV963)',
    'Developer ID Application: TablePlus Inc (3X57WP8E8V)',
    'Developer ID Application: Tenable, Inc. (4B8J598M7U)',
    'Developer ID Application: Valve Corporation (MXGJJ98X76)',
    'Developer ID Application: Wireshark Foundation, Inc. (7Z6EMTD2C6)',
    'Software Signing'
  )
  -- Don't spam alerts with repeated invocations of the same command-line
GROUP BY
  p.cmdline,
  p.cwd,
  p.euid;
