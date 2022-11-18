-- Find programs running from strange directories on macOS
--
-- false positives:
--   - Vendors who are doing weird things that are not in the signature list
--
-- See "execdir-events" for the version that is more likely to catch things
--
-- platform: darwin
-- tags: transient seldom process filesystem state
SELECT
  p.pid,
  p.name,
  p.path,
  p.euid,
  p.gid,
  f.ctime,
  f.directory AS dir,
  REGEX_MATCH (p.path, '(/.*?/.*?/.*?)/', 1) AS top_dir, -- 3 levels deep
  REPLACE(f.directory, u.directory, '~') AS homedir,
  REGEX_MATCH (
    REPLACE(f.directory, u.directory, '~'),
    '(~/.*?/)',
    1
  ) AS top_homedir, -- 1 level deep
  p.cmdline,
  hash.sha256,
  pp.path AS parent_path,
  pp.name AS parent_name,
  pp.cmdline AS parent_cmdline,
  pp.euid AS parent_euid,
  hash.sha256 AS parent_sha256,
  signature.identifier,
  signature.authority
FROM
  processes p
  LEFT JOIN file f ON p.path = f.path
  LEFT JOIN hash ON hash.path = p.path
  LEFT JOIN users u ON p.uid = u.uid
  LEFT JOIN processes pp ON p.parent = pp.pid
  LEFT JOIN signature ON p.path = signature.path
WHERE
  dir NOT IN (
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
    '~/Downloads/google-cloud-sdk/bin',
    '~/go/bin',
    '~/.local/bin',
    '~/.magefile',
    '~/projects/go/bin'
  )
  AND top_homedir NOT IN (
    '~/Applications/',
    '~/bin/',
    '~/code/',
    '~/.config/',
    '~/git/',
    '~/go/',
    '~/.kuberlr/',
    '~/google-cloud-sdk/',
    '~/homebrew/',
    '~/Library/',
    '~/.local/',
    '~/projects/',
    '~/.pulumi/',
    '~/src/',
    '~/.tflint.d/',
    '~/.vscode/',
    '~/.pulumi/',
    '~/.vs-kubernetes/'
  )
  -- Locally built executables
  AND NOT (
    signature.identifier = "a.out"
    AND homedir LIKE '~/%'
    AND pp.name LIKE '%sh'
  )
  AND dir NOT LIKE '/Applications/%'
  AND dir NOT LIKE '/private/tmp/%.app/Contents/MacOS'
  AND dir NOT LIKE '/private/tmp/go-build%/exe'
  AND dir NOT LIKE '/private/tmp/KSInstallAction.%/Install Google Software Update.app/Contents/Helpers'
  AND dir NOT LIKE '/private/tmp/nix-build-%'
  AND dir NOT LIKE '/private/tmp/PKInstallSandbox.%/Scripts/com.microsoft.OneDrive.%'
  AND dir NOT LIKE '/private/var/db/com.apple.xpc.roleaccountd.staging/%.xpc/Contents/MacOS'
  AND dir NOT LIKE '/private/var/folders/%/bin'
  AND dir NOT LIKE '/private/var/folders/%/Contents/%'
  AND dir NOT LIKE '/private/var/folders/%/d/Wrapper/%.app'
  AND dir NOT LIKE '/private/var/folders/%/go-build%'
  AND dir NOT LIKE '/private/var/folders/%/GoLand'
  AND dir NOT LIKE '%/.terraform/providers/%'
  AND dir NOT LIKE '/Volumes/com.getdropbox.dropbox-%'
  AND homedir NOT LIKE '~/Library/Caches/ms-playwright/%'
  AND homedir NOT LIKE '~/%/node_modules/.pnpm/esbuild-%/node_modules/esbuild-darwin-arm64/bin'
  -- Allow these anywhere (put last because it's slow to query signatures)
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
