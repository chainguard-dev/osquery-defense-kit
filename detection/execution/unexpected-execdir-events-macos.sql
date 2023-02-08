-- Catch applications running from unusual directories, such as /tmp
--
-- references:
--   * https://attack.mitre.org/techniques/T1074/
--
-- false positives:
--   * software installers and updaters
--   * developers running programs out of /tmp
--
-- interval: 240
-- platform: darwin
-- tags: filesystem events
SELECT
  -- Child
  pe.path AS p0_path,
  REGEX_MATCH (pe.path, '.*/(.*)', 1) AS p0_name,
  REGEX_MATCH (p.path, '(.*)/', 1) AS dir,
  REGEX_MATCH (p.path, '(/.*?/.*?/.*?)/', 1) AS top_dir, -- 3 levels deep
  REPLACE(f.directory, u.directory, '~') AS homedir,
  REGEX_MATCH (
    REPLACE(f.directory, u.directory, '~'),
    '(~/.*?/.*?/.*?/)',
    1
  ) AS top3_homedir,
  REGEX_MATCH (
    REPLACE(f.directory, u.directory, '~'),
    '(~/.*?/)',
    1
  ) AS top_homedir, -- 1 level deep
  TRIM(pe.cmdline) AS p0_cmd,
  pe.cwd AS p0_cwd,
  pe.pid AS p0_pid,
  pe.euid AS p0_euid,
  -- Parent
  pe.parent AS p1_pid,
  TRIM(COALESCE(p1.cmdline, pe1.cmdline)) AS p1_cmd,
  COALESCE(p1.path, pe1.path) AS p1_path,
  COALESCE(p_hash1.sha256, pe_hash1.sha256) AS p1_hash,
  REGEX_MATCH (COALESCE(p1.path, pe1.path), '.*/(.*)', 1) AS p1_name,
  -- Grandparent
  COALESCE(p1.parent, pe1.parent) AS p2_pid,
  TRIM(
    COALESCE(p1_p2.cmdline, pe1_p2.cmdline, pe1_pe2.cmdline)
  ) AS p2_cmd,
  COALESCE(p1_p2.path, pe1_p2.path, pe1_pe2.path) AS p2_path,
  COALESCE(
    p1_p2_hash.path,
    pe1_p2_hash.path,
    pe1_pe2_hash.path
  ) AS p2_hash,
  REGEX_MATCH (
    COALESCE(p1_p2.path, pe1_p2.path, pe1_pe2.path),
    '.*/(.*)',
    1
  ) AS p2_name
FROM
  process_events pe
  LEFT JOIN file f ON pe.path = f.path
  LEFT JOIN signature S ON pe.path = s.path
  LEFT JOIN users u ON pe.euid = u.uid
  LEFT JOIN processes p ON pe.pid = p.pid
  -- Parents (via two paths)
  LEFT JOIN processes p1 ON pe.parent = p1.pid
  LEFT JOIN hash p_hash1 ON p1.path = p_hash1.path
  LEFT JOIN process_events pe1 ON pe.parent = pe1.pid
  AND pe1.cmdline != ''
  LEFT JOIN hash pe_hash1 ON pe1.path = pe_hash1.path
  -- Grandparents (via 3 paths)
  LEFT JOIN processes p1_p2 ON p1.parent = p1_p2.pid -- Current grandparent via parent processes
  LEFT JOIN processes pe1_p2 ON pe1.parent = pe1_p2.pid -- Current grandparent via parent events
  LEFT JOIN process_events pe1_pe2 ON pe1.parent = pe1_p2.pid
  AND pe1_pe2.cmdline != '' -- Past grandparent via parent events
  LEFT JOIN hash p1_p2_hash ON p1_p2.path = p1_p2_hash.path
  LEFT JOIN hash pe1_p2_hash ON pe1_p2.path = pe1_p2_hash.path
  LEFT JOIN hash pe1_pe2_hash ON pe1_pe2.path = pe1_pe2_hash.path
WHERE
  pe.time > (strftime('%s', 'now') -240)
  -- The process_events table on macOS ends up with relative directories for some reason?
  AND dir LIKE '/%'
  AND f.size > 0
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
    '~/Downloads/google-cloud-sdk/bin',
    '~/Library/Application Support/dev.warp.Warp-Stable',
    '~/go/bin',
    '~/Library/Application Support/cloud-code/installer/google-cloud-sdk/bin',
    '~/.local/bin',
    '~/.magefile',
    '~/Downloads/protoc/bin',
    '~/projects/go/bin'
  )
  AND top3_homedir NOT IN (
    '~/Library/Application Support/com.elgato.StreamDeck/',
    '~/Library/Caches/snyk/',
    '~/Library/Application Support/BraveSoftware/'
  )
  AND top_homedir NOT IN (
    '~/Applications/',
    '~/Applications (Parallels)/',
    '~/bin/',
    '~/.cargo/',
    '~/chainguard/',
    '~/code/',
    '~/Code/',
    '~/.config/',
    '~/git/',
    '~/github/',
    '~/go/',
    '~/google-cloud-sdk/',
    '~/homebrew/',
    '~/.kuberlr/',
    --  '~/Library/',
    '~/.gradle/',
    '~/.local/',
    '~/Parallels/',
    '~/proj/',
    '~/projects/',
    '~/Projects/',
    '~/.pulumi/',
    '~/.provisio/',
    '~/.pyenv/',
    '~/.rustup/',
    '~/src/',
    '~/.tflint.d/',
    '~/.vscode/',
    '~/.vs-kubernetes/'
  )
  -- Locally built executables
  AND NOT (
    s.identifier = 'a.out'
    AND homedir LIKE '~/%'
    AND p1_name IN ('fish', 'sh', 'bash', 'zsh', 'terraform', 'code')
  )
  AND NOT (
    s.authority = ''
    AND homedir LIKE '~/%'
    AND p1_name IN ('fish', 'sh', 'bash', 'zsh')
    AND p.cmdline LIKE './%'
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
  AND dir NOT LIKE '/private/var/folders/%/Contents/%'
  AND dir NOT LIKE '/private/var/folders/%/d/Wrapper/%.app'
  AND dir NOT LIKE '/private/var/folders/%/go-build%'
  AND dir NOT LIKE '/private/var/folders/%/GoLand'
  AND dir NOT LIKE '%/.terraform/providers/%'
  AND dir NOT LIKE '/Volumes/com.getdropbox.dropbox-%'
  AND homedir NOT LIKE '~/%/google-cloud-sdk/bin/%'
  AND homedir NOT LIKE '~/Library/Caches/ms-playwright/%'
  AND homedir NOT LIKE '~/%/node_modules/.pnpm/%'
  AND homedir NOT LIKE '~/%repo%'
  AND homedir NOT LIKE '~/.local/%/packages/%'
  AND homedir NOT LIKE '~/%sigstore%'
  AND homedir NOT LIKE '~/%/bin'
  AND homedir NOT LIKE '~/Library/Printers/%/Contents/MacOS'
  -- These signers can run from wherever the hell they want.
  AND s.authority NOT IN (
    'Apple iPhone OS Application Signing',
    'Apple Mac OS Application Signing',
    'Developer ID Application: Adobe Inc. (JQ525L2MZD)',
    'Developer ID Application: Cisco (DE8Y96K9QP)',
    'Developer ID Application: CodeWeavers Inc. (9C6B7X7Z8E)',
    'Developer ID Application: Sublime HQ Pty Ltd (Z6D26JE4Y4)',
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
