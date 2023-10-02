-- Find programs running from strange directories on macOS
--
-- false positives:
--   - Vendors who are doing weird things that are not in the signature list
--
-- See "execdir-events" for the version that is more likely to catch things
--
-- platform: darwin
-- tags: transient seldom process filesystem state
SELECT DISTINCT
  COALESCE(REGEX_MATCH (p0.path, '(.*)/', 1), p0.path) AS dir,
  REPLACE(f.directory, u.directory, '~') AS homedir,
  COALESCE(
    REGEX_MATCH (
      REPLACE(f.directory, u.directory, '~'),
      '(~/.*?/.*?/.*?/)',
      1
    ),
    REPLACE(f.directory, u.directory, '~')
  ) AS top3_homedir,
  REGEX_MATCH (
    REPLACE(f.directory, u.directory, '~'),
    '(~/.*?/)',
    1
  ) AS top_homedir,
  s.authority AS p0_auth,
  s.identifier AS p0_id,
  -- Child
  p0.pid AS p0_pid,
  p0.start_time AS p0_start,
  p0.path AS p0_path,
  p0.name AS p0_name,
  p0.cmdline AS p0_cmd,
  p0.cwd AS p0_cwd,
  p0.euid AS p0_euid,
  p0_hash.sha256 AS p0_sha256,
  -- Parent
  p0.parent AS p1_pid,
  p1.start_time AS p1_start,
  p1.path AS p1_path,
  p1.name AS p1_name,
  p1_f.mode AS p1_mode,
  p1.euid AS p1_euid,
  p1.cmdline AS p1_cmd,
  p1_hash.sha256 AS p1_sha256,
  -- Grandparent
  p1.parent AS p2_pid,
  p2.name AS p2_name,
  p2.path AS p2_path,
  p2.cmdline AS p2_cmd,
  p2_hash.sha256 AS p2_sha256
FROM
  processes p0
  LEFT JOIN file f ON p0.path = f.path
  LEFT JOIN users u ON p0.uid = u.uid
  LEFT JOIN signature s ON p0.path = s.path
  LEFT JOIN hash p0_hash ON p0.path = p0_hash.path
  LEFT JOIN processes p1 ON p0.parent = p1.pid
  LEFT JOIN file p1_f ON p1.path = p1_f.path
  LEFT JOIN hash p1_hash ON p1.path = p1_hash.path
  LEFT JOIN processes p2 ON p1.parent = p2.pid
  LEFT JOIN hash p2_hash ON p2.path = p2_hash.path
WHERE
  p0.pid IN (
    SELECT
      pid
    FROM
      processes
    WHERE
      pid > 0
      AND REGEX_MATCH (
        path,
        "^(/System|/usr/libexec/|/usr/sbin/|/usr/bin/|/usr/lib/|/bin/|/Applications|/Library/Apple/|/sbin/|/usr/local/kolide-k2)",
        1
      ) IS NULL
    GROUP BY
      path
  )
  AND NOT dir IN (
    '/Library/Application Support/Logitech.localized/Logitech Options.localized/LogiMgrUpdater.app/Contents/Resources',
    '/Library/DropboxHelperTools/Dropbox_u501',
    '/Library/Filesystems/kbfuse.fs/Contents/Resources',
    '/Library/Frameworks/Python.framework/Versions/3.10/bin',
    '/Library/Google/GoogleSoftwareUpdate/GoogleSoftwareUpdate.bundle/Contents/Helpers.app/Contents/MacOS',
    '/Library/Google/GoogleSoftwareUpdate/GoogleSoftwareUpdate.bundle/Contents/Helpers/GoogleSoftwareUpdateAgent.app/Contents/MacOS',
    '/Library/Printers/DYMO/Utilities',
    '/Library/Kandji/Kandji Agent.app/Contents/MacOS/',
    '/Library/Application Support/Kandji/Kandji Menu/Kandji Menu.app/Contents/MacOS',
    '/Library/PrivilegedHelperTools',
    '/Library/TeX/texbin',
    '/usr/local/aws-cli',
    '/nix/store',
    '/nix/var/nix/profiles/default/bin',
    '/opt/homebrew/Caskroom/google-cloud-sdk/latest/google-cloud-sdk/bin/gke-gcloud-auth-plugin',
    '/opt/usr/bin',
    '/opt/X11/bin',
    '/opt/X11/libexec',
    '/run/current-system/sw/bin'
  )
  AND NOT homedir IN (
    '~/bin',
    '~/.cache/gitstatus',
    '~/.gvm/binscripts',
    '~/.local/share/gh/extensions/gh-sbom',
    '~/.magefile'
  )
  AND NOT homedir LIKE '~/%/bin'
  AND NOT homedir LIKE '~/Downloads/%.app/Contents/MacOS'
  AND NOT top_homedir IN (
    '~/Applications/',
    '~/Applications (Parallels)/',
    '~/bin/',
    '~/.cargo/',
    '~/code/',
    '~/.Trash/',
    '~/Code/',
    '~/.steampipe/',
    '~/.config/',
    '~/dev/',
    '~/git/',
    '~/go/',
    '~/google-cloud-sdk/',
    '~/homebrew/',
    '~/.kuberlr/',
    '~/Parallels/',
    '~/proj/',
    '~/projects/',
    '~/.provisio/',
    '~/.pulumi/',
    '~/.pyenv/',
    '~/.rbenv/',
    '~/.rustup/',
    '~/sigstore/',
    '~/src/',
    '~/.tflint.d/',
    '~/.vscode/',
    '~/.vs-kubernetes/'
  )
  AND NOT top3_homedir IN (
    '/Library/Application Support/EcammLive',
    '~/Library/Caches/com.mimestream.Mimestream/',
    '~/Library/Caches/com.sempliva.Tiles/',
    '~/Library/Services/UE4EditorServices.app/',
    '~/Library/Caches/com.grammarly.ProjectLlama/',
    '~/Library/Caches/JetBrains/',
    '~/Library/Caches/Cypress/',
    '~/Library/Caches/org.gpgtools.updater/',
    '~/Library/Caches/snyk/',
    '/Library/Developer/Xcode/',
    '~/.terraform.d/plugin-cache/registry.terraform.io/'
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
  AND homedir NOT LIKE '~/%/google-cloud-sdk/bin/%'
  AND homedir NOT LIKE '~/Library/Caches/ms-playwright/%'
  AND homedir NOT LIKE '~/%/node_modules/%'
  AND homedir NOT LIKE '~/.local/%/packages/%'
  AND homedir NOT LIKE '~/Library/Printers/%/Contents/MacOS'
  AND homedir NOT LIKE '~/Library/Caches/%/org.sparkle-project.Sparkle/Launcher/%/Updater.app/Contents/MacOS'
  AND homedir NOT LIKE '~/Library/Application Support/%'
  AND s.authority NOT IN (
    'Apple iPhone OS Application Signing',
    'Apple Mac OS Application Signing',
    'Developer ID Application: Adobe Inc. (JQ525L2MZD)',
    'Developer ID Application: Cisco (DE8Y96K9QP)',
    'Developer ID Application: CodeWeavers Inc. (9C6B7X7Z8E)',
    'Developer ID Application: Corsair Memory, Inc. (Y93VXCB8Q5)',
    'Developer ID Application: Docker Inc (9BNSXJN65R)',
    'Developer ID Application: Dropbox, Inc. (G7HH3F8CAK)',
    'Developer ID Application: EnterpriseDB Corporation (26QKX55P9K)',
    'Developer ID Application: Epic Games International, S.a.r.l. (96DBZ92D3Y)',
    'Developer ID Application: Figma, Inc. (T8RA8NE3B7)',
    'Developer ID Application: GEORGE NACHMAN (H7V7XYVQ7D)',
    'Developer ID Application: Google LLC (EQHXZ8M8AV)',
    'Developer ID Application: Hashicorp, Inc. (D38WU7D763)',
    'Developer ID Application: Hercules Labs Inc. (B8PC799ZGU)',
    'Developer ID Application: JetBrains s.r.o. (2ZEFAR8TH3)',
    'Developer ID Application: Logitech Inc. (QED4VVPZWA)',
    'Developer ID Application: Microsoft Corporation (UBF8T346G9)',
    'Developer ID Application: Node.js Foundation (HX7739G8FX)',
    'Developer ID Application: Objective Development Software GmbH (MLZF7K7B5R)',
    'Developer ID Application: Objective-See, LLC (VBG97UB4TA)',
    'Developer ID Application: Opal Camera Inc (97Z3HJWCRT)',
    'Developer ID Application: Oracle America, Inc. (VB5E2TV963)',
    'Developer ID Application: Sublime HQ Pty Ltd (Z6D26JE4Y4)',
    'Developer ID Application: TablePlus Inc (3X57WP8E8V)',
    'Developer ID Application: Tenable, Inc. (4B8J598M7U)',
    'Developer ID Application: Valve Corporation (MXGJJ98X76)',
    'Developer ID Application: Wireshark Foundation, Inc. (7Z6EMTD2C6)',
    'Software Signing'
  ) -- Locally built executables
  AND NOT (
    s.identifier = "a.out"
    AND homedir LIKE '~/%'
    AND p1.name LIKE '%sh'
    AND p2.name = 'login'
    AND p0.path NOT LIKE '%/Cache%'
    AND p0.path NOT LIKE '%/Library/%'
    AND p0.path NOT LIKE '%/.%'
  )
