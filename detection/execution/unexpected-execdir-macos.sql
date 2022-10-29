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
  f.directory AS dirname,
  REPLACE(f.directory, u.directory, '~') AS dirname,
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
  LEFT JOIN signature ON p.path = signature.path -- NOTE: Everything after this is shared with process_events/unexpected-executable-directory-events
WHERE
  dirname NOT IN (
    '/bin',
    '/Library/DropboxHelperTools/Dropbox_u501',
    '/Library/Filesystems/kbfuse.fs/Contents/Resources',
    '/Library/Google/GoogleSoftwareUpdate/GoogleSoftwareUpdate.bundle/Contents/Helpers/GoogleSoftwareUpdateAgent.app/Contents/MacOS',
    '/Library/Printers/DYMO/Utilities',
    '/Library/PrivilegedHelperTools',
    '/opt/homebrew/Caskroom/google-cloud-sdk/latest/google-cloud-sdk/bin/gke-gcloud-auth-plugin',
    '/opt/usr/bin',
    '/opt/X11/bin',
    '/opt/X11/libexec',
    '/sbin',
    '/usr/bin',
    '/usr/lib',
    '/usr/lib/bluetooth',
    '/usr/lib/cups/notifier',
    '/usr/lib/fwupd',
    '/usr/lib/ibus',
    '/usr/libexec',
    '/usr/libexec/ApplicationFirewall',
    '/usr/libexec/AssetCache',
    '/usr/libexec/rosetta',
    '/usr/sbin',
    '/usr/share/code',
    '/usr/share/teams/resources/app.asar.unpacked/node_modules/slimcore/bin'
  )
  AND homedir NOT IN (
    '~/bin',
    '~/go/bin',
    '~/Library/Application Support/cloud-code/installer/google-cloud-sdk/bin',
    '~/Library/Application Support/Code/User/globalStorage/grafana.vscode-jsonnet/bin',
    '~/Library/Application Support/com.elgato.StreamDeck/Plugins/com.lostdomain.zoom.sdPlugin'
  )
  AND signature.authority NOT IN (
    'Apple Mac OS Application Signing',
    'Developer ID Application: Adobe Inc. (JQ525L2MZD)',
    'Developer ID Application: Corsair Memory, Inc. (Y93VXCB8Q5)',
    'Developer ID Application: Docker Inc (9BNSXJN65R)',
    'Developer ID Application: Dropbox, Inc. (G7HH3F8CAK)',
    'Developer ID Application: Figma, Inc. (T8RA8NE3B7)',
    'Developer ID Application: Google LLC (EQHXZ8M8AV)',
    'Developer ID Application: CodeWeavers Inc. (9C6B7X7Z8E)',
    'Developer ID Application: GEORGE NACHMAN (H7V7XYVQ7D)',
    'Developer ID Application: Hashicorp, Inc. (D38WU7D763)',
    'Developer ID Application: Logitech Inc. (QED4VVPZWA)',
    'Developer ID Application: Microsoft Corporation (UBF8T346G9)',
    'Developer ID Application: Objective Development Software GmbH (MLZF7K7B5R)',
    'Developer ID Application: Objective-See, LLC (VBG97UB4TA)',
    'Developer ID Application: Opal Camera Inc (97Z3HJWCRT)',
    'Developer ID Application: Oracle America, Inc. (VB5E2TV963)',
    'Developer ID Application: Oracle America, Inc. (VB5E2TV963)',
    'Developer ID Application: Tenable, Inc. (4B8J598M7U)',
    'Developer ID Application: Valve Corporation (MXGJJ98X76)',
    'Developer ID Application: Wireshark Foundation, Inc. (7Z6EMTD2C6)',
    'Apple iPhone OS Application Signing',
    'Developer ID Application: Node.js Foundation (HX7739G8FX)',
    'Software Signing'
  )
  AND homedir NOT LIKE '~/%/node_modules/.pnpm/esbuild-%/node_modules/esbuild-darwin-arm64/bin'
  AND dirname NOT LIKE '/private/var/folders/%/d/Wrapper/%.app'
  AND dirname NOT LIKE '/Applications/%.app/%'
  AND dirname NOT LIKE '/Applications/Utilities/Adobe Creative Cloud/%'
  AND dirname NOT LIKE '/Library/%/%.bundle/Contents/Helpers'
  AND dirname NOT LIKE '/Library/%/Resources/%/Contents/MacOS'
  AND dirname NOT LIKE '/Library/%/sbin' -- Nessus
  AND dirname NOT LIKE '/Library/Apple/System/Library%'
  AND dirname NOT LIKE '/Library/Application Support/%/Contents/MacOS'
  AND dirname NOT LIKE '/Library/Application Support/Adobe/%'
  AND dirname NOT LIKE '/Library/Audio/Plug-Ins/%/Contents/MacOS'
  AND dirname NOT LIKE '/Library/CoreMediaIO/Plug-Ins/%'
  AND dirname NOT LIKE '/Library/Developer/%'
  AND dirname NOT LIKE '/Library/Developer/CommandLineTools/Library/%'
  AND dirname NOT LIKE '/Library/Internet Plug-Ins/%/Contents/MacOS'
  AND dirname NOT LIKE '/Library/Java/JavaVirtualMachines/%'
  AND dirname NOT LIKE '/Library/Printers/%.app/Contents/MacOS'
  AND dirname NOT LIKE '/Library/PrivilegedHelperTools/com.%'
  AND dirname NOT LIKE '/nix/store/%'
  AND dirname NOT LIKE '/opt/homebrew/Cellar/%/bin'
  AND dirname NOT LIKE '/opt/homebrew/Cellar/%/libexec'
  AND dirname NOT LIKE '/opt/homebrew/Cellar/%/libexec/%'
  AND dirname NOT LIKE '/opt/homebrew/Cellar/%/Contents/MacOS'
  AND dirname NOT LIKE '/opt/homebrew/Caskroom/%/bin'
  AND dirname NOT LIKE '/private/tmp/%.app/Contents/MacOS'
  AND dirname NOT LIKE '/private/tmp/go-build%/exe'
  AND dirname NOT LIKE '/private/tmp/nix-build-%'
  AND dirname NOT LIKE '/private/tmp/PKInstallSandbox.%/Scripts/com.microsoft.OneDrive.%'
  AND dirname NOT LIKE '/private/var/db/com.apple.xpc.roleaccountd.staging/%.xpc/Contents/MacOS'
  AND dirname NOT LIKE '/private/var/folders/%/bin'
  AND dirname NOT LIKE '/private/var/folders/%/Contents/%'
  AND dirname NOT LIKE '/private/var/folders/%/go-build%'
  AND dirname NOT LIKE '/private/var/folders/%/GoLand'
  AND dirname NOT LIKE '/System/%'
  AND dirname NOT LIKE '/Users/%/bin/%'
  AND dirname NOT LIKE '/Users/%/src/%'
  AND dirname NOT LIKE '/usr/libexec/%'
  AND dirname NOT LIKE '/usr/local/%'
  AND NOT (
    dirname LIKE '/private/var/%'
    AND p.name LIKE 'pulumi-go.%'
  ) -- Chrome executes patches from /tmp :(
  AND NOT (
    dirname LIKE '/private/tmp/%'
    AND p.name = 'goobspatch'
  )
  AND NOT (
    homedir = '~'
    AND p.name = 'cloud_sql_proxy'
  )
