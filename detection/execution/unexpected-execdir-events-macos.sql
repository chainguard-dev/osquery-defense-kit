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
  COALESCE(
    REGEX_MATCH (REPLACE(pe.path, u.directory, '~'), '(.*)/', 1),
    pe.path
  ) AS dir,
  COALESCE(
    REGEX_MATCH (
      REPLACE(pe.path, u.directory, '~'),
      '(~*/.*?)/',
      1
    ),
    REPLACE(pe.path, u.directory, '~'),
    '(.*)/',
    1
  ) AS top1_dir,
  COALESCE(
    REGEX_MATCH (
      REPLACE(pe.path, u.directory, '~'),
      '(~*/.*?/.*?/.*?)/',
      1
    ),
    REPLACE(pe.path, u.directory, '~'),
    '(.*)/',
    1
  ) AS top3_dir,
  s.identifier AS s_id,
  s.authority AS s_auth,
  -- Child
  pe.path AS p0_path,
  COALESCE(REGEX_MATCH (pe.path, '.*/(.*)', 1), pe.path) AS p0_name,
  TRIM(pe.cmdline) AS p0_cmd,
  pe.time AS p0_time,
  -- pe.cwd is NULL on macOS
  p.cwd AS p0_cwd,
  pe.pid AS p0_pid,
  pe.euid AS p0_euid,
  -- Parent
  pe.parent AS p1_pid,
  TRIM(COALESCE(p1.cmdline, pe1.cmdline)) AS p1_cmd,
  p1.cwd AS p1_cwd,
  COALESCE(p1.path, pe1.path) AS p1_path,
  COALESCE(p_hash1.sha256, pe_hash1.sha256) AS p1_hash,
  REGEX_MATCH (COALESCE(p1.path, pe1.path), '.*/(.*)', 1) AS p1_name,
  -- Grandparent
  COALESCE(p1.parent, pe1.parent) AS p2_pid,
  TRIM(
    COALESCE(p1_p2.cmdline, pe1_p2.cmdline, pe1_pe2.cmdline)
  ) AS p2_cmd,
  p1_p2.cwd AS p2_cwd,
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
  LEFT JOIN users u ON pe.uid = u.uid
  LEFT JOIN processes p ON pe.pid = p.pid -- Parents (via two paths)
  LEFT JOIN processes p1 ON pe.parent = p1.pid
  LEFT JOIN hash p_hash1 ON p1.path = p_hash1.path
  LEFT JOIN process_events pe1 ON pe.parent = pe1.pid
  AND pe1.cmdline != ''
  LEFT JOIN hash pe_hash1 ON pe1.path = pe_hash1.path -- Grandparents (via 3 paths)
  LEFT JOIN processes p1_p2 ON p1.parent = p1_p2.pid -- Current grandparent via parent processes
  LEFT JOIN processes pe1_p2 ON pe1.parent = pe1_p2.pid -- Current grandparent via parent events
  LEFT JOIN process_events pe1_pe2 ON pe1.parent = pe1_p2.pid
  AND pe1_pe2.cmdline != '' -- Past grandparent via parent events
  LEFT JOIN hash p1_p2_hash ON p1_p2.path = p1_p2_hash.path
  LEFT JOIN hash pe1_p2_hash ON pe1_p2.path = pe1_p2_hash.path
  LEFT JOIN hash pe1_pe2_hash ON pe1_pe2.path = pe1_pe2_hash.path
WHERE
  pe.time > (strftime('%s', 'now') -240)
  AND pe.status = 0
  AND pe.cmdline != ''
  AND pe.cmdline IS NOT NULL
  AND top1_dir NOT IN (
    '~/Applications',
    '/Applications',
    '~/Applications (Parallels)',
    '~/bin',
    '~/.cargo',
    '~/melange',
    '~/chainctl',
    '~/chainguard',
    '~/dev',
    '~/code',
    '~/Code',
    '~/.config',
    '~/.gimme',
    '~/git',
    '~/github',
    '~/go',
    '~/google-cloud-sdk',
    '~/.gradle',
    '~/homebrew',
    '~/.kuberlr',
    --  '~/Library',
    '~/.local',
    '/nix',
    '~/Parallels',
    '~/proj',
    '~/projects',
    '~/Projects',
    '~/workspace',
    '~/.provisio',
    '~/.pulumi',
    '~/.pyenv',
    '~/.rustup',
    '~/src',
    '~/.steampipe',
    '/System',
    '~/.tflint.d',
    '~/.vscode',
    '~/.vs-kubernetes'
  )
  AND top3_dir NOT IN (
    '/Library/Apple/System',
    '/Library/Application Support/Adobe',
    '/Library/Application Support/Blackmagic Design',
    '/Library/Application Support/Canon_Inc_IC',
    '/Library/Application Support/EcammLive',
    '/Library/Application Support/Fortinet',
    '/Library/Application Support/GPGTools',
    '/Library/Application Support/com.canonical.multipass',
    '/Library/Application Support/org.pqrs',
    '~/Library/Application Support/Steam',
    '/Library/Developer/CommandLineTools',
    '/Library/Screen Savers/XScreenSaverUpdater.app',
    '/Library/Google/GoogleSoftwareUpdate',
    '/Library/Java/JavaVirtualMachines',
    '/Library/Plug-Ins/FxPlug',
    '/Library/Printers/Canon',
    '/Volumes/Google Chrome/Google Chrome.app',
    '/Volumes/Slack/Slack.app',
    '/opt/homebrew/Caskroom',
    '/opt/homebrew/Cellar',
    '/opt/homebrew/Library',
    '/private/var/kolide-k2',
    '/usr/libexec/AssetCache',
    '/usr/libexec/rosetta',
    '/usr/local/Cellar',
    '/usr/local/kolide-k2',
    '~/.docker/cli-plugins',
    '~/.docker/cli-plugins/docker-sbom',
    '~/.wdm/drivers/chromedriver',
    '~/Library/Application Support/BraveSoftware',
    '~/Library/Application Support/CleanMyMac X',
    '~/Library/Application Support/Foxit Software',
    '~/Library/Application Support/JetBrains',
    '~/Library/Application Support/LogMeInInc',
    '~/Library/Application Support/com.elgato.StreamDeck',
    '~/Library/Application Support/com.grammarly.ProjectLlama',
    '~/Library/Application Support/minecraft',
    '~/Library/Application Support/zoom.us',
    '~/Library/Caches/Cypress',
    '~/Library/Caches/JetBrains',
    '~/Library/Caches/com.knollsoft.Rectangle',
    '~/Library/Caches/com.mimestream.Mimestream',
    '~/Library/Caches/snyk',
    '~/Library/Developer/Xcode',
    '~/Library/Google/GoogleSoftwareUpdate',
    '~/Library/Services/UE4EditorServices.app'
  )
  AND dir NOT IN (
    '/Library/Application Support/Fortinet/FortiClient/bin',
    '/Library/Application Support/Kandji/Kandji Menu/Kandji Menu.app/Contents/MacOS',
    '/Library/Application Support/Logitech.localized/LogiOptionsPlus/logioptionsplus_agent.app/Contents/MacOS',
    '/Library/Application Support/Logitech.localized/Logitech Options.localized/LogiMgrUpdater.app/Contents/Resources',
    '/Library/Application Support/X-Rite/Frameworks/XRiteDevice.framework/Versions/B/Resources/XRD Software Update.app/Contents/MacOS',
    '/Library/Audio/Plug-Ins/HAL/ACE.driver/Contents/Resources',
    '/Library/Audio/Plug-Ins/HAL/ACE.driver/Contents/Resources/aceagent.app/Contents/MacOS',
    '/Library/Audio/Plug-Ins/HAL/SolsticeDesktopSpeakers.driver/Contents/XPCServices/RelayXpc.xpc/Contents/MacOS',
    '/Library/DropboxHelperTools/Dropbox_u501',
    '/Library/Filesystems/kbfuse.fs/Contents/Resources',
    '/Library/Filesystems/macfuse.fs/Contents/Resources',
    '/Library/Frameworks/Python.framework/Versions/3.10/bin',
    '/Library/Google/GoogleSoftwareUpdate/GoogleSoftwareUpdate.bundle/Contents/Helpers.app/Contents/MacOS',
    '/Library/Google/GoogleSoftwareUpdate/GoogleSoftwareUpdate.bundle/Contents/Helpers/GoogleSoftwareUpdateAgent.app/Contents/MacOS',
    '/Library/Image Capture/Devices/EPSON Scanner.app/Contents/MacOS',
    '/Library/Kandji/Kandji Agent.app/Contents/MacOS',
    '/Library/Kandji/Kandji Agent.app/Contents/MacOS/',
    '/Library/Printers/Brother/Filter/rastertobrother2130.bundle/Contents/MacOS',
    '/Library/Printers/Brother/Filter/rastertobrother2300.bundle/Contents/MacOS',
    '/Library/Printers/Brother/Utilities/Server/LOGINserver.app/Contents/MacOS',
    '/Library/Printers/Brother/Utilities/Server/NETserver.app/Contents/MacOS',
    '/Library/Printers/Brother/Utilities/Server/USBAppControl.app/Contents/MacOS',
    '/Library/Printers/Brother/Utilities/Server/WorkflowAppControl.app/Contents/MacOS',
    '/Library/Printers/DYMO/Utilities',
    '/Library/Printers/EPSON/InkjetPrinter2/Filter/commandtoescp.app/Contents/MacOS',
    '/Library/PrivilegedHelperTools',
    '/Library/TeX/texbin',
    '/Volumes/Grammarly/Grammarly Installer.app/Contents/MacOS',
    '/bin',
    '/node_modules/.bin',
    '/opt/X11/bin',
    '/opt/X11/libexec',
    '/opt/custom-cli-tools',
    '/opt/homebrew/bin',
    '/opt/osquery/lib/osquery.app/Contents/MacOS',
    '/opt/usr/bin',
    '/run/current-system/sw/bin',
    '/sbin',
    '/tmp/bin',
    '/usr/bin',
    '/usr/lib',
    '/usr/lib/bluetooth',
    '/usr/lib/cups/notifier',
    '/usr/lib/fwupd',
    '/usr/lib/ibus',
    '/usr/lib/system',
    '/usr/libexec',
    '/usr/libexec/ApplicationFirewall',
    '/usr/libexec/AssetCache',
    '/usr/libexec/cups/backend',
    '/usr/libexec/firmwarecheckers',
    '/usr/libexec/firmwarecheckers/eficheck',
    '/usr/libexec/rosetta',
    '/usr/local/MacGPG2/bin',
    '/usr/local/aws-cli',
    '/usr/local/bin',
    '/usr/sbin',
    '~/.cache/gitstatus',
    '~/.docker/cli-plugins',
    '~/.local/bin',
    '~/.magefile',
    '~/Downloads/google-cloud-sdk/bin',
    '~/Downloads/protoc/bin',
    '~/Library/Application Support/Alfred/Assistant',
    '~/Library/Application Support/cloud-code/installer/google-cloud-sdk/bin',
    '~/Library/Application Support/dev.warp.Warp-Stable',
    '~/Library/Application Support/minecraft/launcher/launcher.bundle/Contents/Frameworks/launcher-Helper (GPU).app/Contents/MacOS',
    '~/Library/Application Support/snyk-ls',
    '~/bin',
    '~/code/bin',
    '~/go/bin',
    '~/melange',
    '~/projects/go/bin'
  ) -- Locally built executables
  AND NOT (
    s.identifier = 'a.out'
    AND (
      dir LIKE '~/%'
      OR dir LIKE '/Users/%'
    )
    AND p1_name IN ('fish', 'sh', 'bash', 'zsh', 'terraform', 'code')
  )
  AND NOT (
    s.authority = ''
    AND dir LIKE '~/%'
    AND p1_name IN ('fish', 'sh', 'bash', 'zsh')
    AND p.cmdline LIKE './%'
  ) -- Spotify
  AND pe.path NOT LIKE '/private/var/folders/%/T/sp_relauncher' -- Sparkle updater
  AND pe.path NOT LIKE '/private/tmp%/cloud_sql_proxy'
  AND pe.path NOT LIKE '/Users/%/Library/Caches/%/org.sparkle-project.Sparkle/Launcher/%/Updater.app/Contents/MacOS/Updater'
  AND dir NOT LIKE '/Applications/%'
  AND dir NOT LIKE '~/%/bin'
  AND dir NOT LIKE '~/Downloads/%.app/Contents/MacOS'
  AND dir NOT LIKE '~/Documents/%/build/%'
  AND dir NOT LIKE '~/Documents/%/target/%'
  AND dir NOT LIKE '~/%/google-cloud-sdk/bin/%'
  AND dir NOT LIKE '~/Library/Caches/ms-playwright/%'
  AND dir NOT LIKE '~/Library/Printers/%/Contents/MacOS'
  AND dir NOT LIKE '/Library/SystemExtensions/%-%/%.systemextension/Contents/MacOS'
  AND dir NOT LIKE '~/.local/%/packages/%'
  AND dir NOT LIKE '~/%/node_modules/%'
  AND dir NOT LIKE '/opt/%/bin'
  AND dir NOT LIKE '/private/tmp/%.app/Contents/MacOS'
  AND dir NOT LIKE '/private/tmp/go-build%/exe'
  AND dir NOT LIKE '%/go/bin'
  AND dir NOT LIKE '/private/tmp/KSInstallAction.%/Install Google Software Update.app/Contents/Helpers'
  AND dir NOT LIKE '/private/tmp/nix-build-%'
  AND dir NOT LIKE '/private/var/folders/%/T/cargo-install%'
  AND dir NOT LIKE '/private/tmp/PKInstallSandbox.%/Scripts/com.microsoft.OneDrive.%'
  AND dir NOT LIKE '/private/var/db/com.apple.xpc.roleaccountd.staging/%.xpc/Contents/MacOS'
  AND dir NOT LIKE '/private/var/folders/%/bin'
  AND dir NOT LIKE '/private/var/folders/%/Contents/%'
  AND dir NOT LIKE '/private/var/folders/%/d/Wrapper/%.app%'
  AND dir NOT LIKE '/private/var/folders/%/go-build%'
  AND dir NOT LIKE '/private/var/folders/%/GoLand'
  AND dir NOT LIKE '/private/var/kolide-k2/k2device.kolide.com/updates/osqueryd/%'
  AND dir NOT LIKE '~/%repo%' -- When running code as root
  AND dir NOT LIKE '~/%sigstore%'
  AND dir NOT LIKE '%/.terraform/providers/%'
  AND dir NOT LIKE '/Volumes/com.getdropbox.dropbox-%' -- These signers can run from wherever the hell they want.
  AND s.identifier != 'org.sparkle-project.Sparkle.Autoupdate'
  AND s.authority NOT IN (
    'Apple iPhone OS Application Signing',
    'Apple Mac OS Application Signing',
    'Developer ID Application: Adobe Inc. (JQ525L2MZD)',
    'Developer ID Application: Brother Industries, LTD. (5HCL85FLGW)',
    'Developer ID Application: Canonical Group Limited (X4QN7LTP59)',
    'Developer ID Application: Cisco (DE8Y96K9QP)',
    'Developer ID Application: CodeWeavers Inc. (9C6B7X7Z8E)',
    'Developer ID Application: Canon Inc. (XE2XNRRXZ5)',
    'Developer ID Application: Corsair Memory, Inc. (Y93VXCB8Q5)',
    'Developer ID Application: Docker Inc (9BNSXJN65R)',
    'Developer ID Application: Dropbox, Inc. (G7HH3F8CAK)',
    'Developer ID Application: Epic Games International, S.a.r.l. (96DBZ92D3Y)',
    'Developer ID Application: Figma, Inc. (T8RA8NE3B7)',
    'Developer ID Application: Fortinet, Inc (AH4XFXJ7DK)',
    'Developer ID Application: GEORGE NACHMAN (H7V7XYVQ7D)',
    'Developer ID Application: Google LLC (EQHXZ8M8AV)',
    'Developer ID Application: Hashicorp, Inc. (D38WU7D763)',
    'Developer ID Application: Keybase, Inc. (99229SGT5K)',
    'Developer ID Application: LG Electronics (5SKT5H4CPQ)',
    'Developer ID Application: Logitech Inc. (QED4VVPZWA)',
    'Developer ID Application: MacPaw Inc. (S8EX82NJP6)',
    'Developer ID Application: Microsoft Corporation (UBF8T346G9)',
    'Developer ID Application: Mojang AB (HR992ZEAE6)',
    'Developer ID Application: Ned Deily (DJ3H93M7VJ)',
    'Developer ID Application: Node.js Foundation (HX7739G8FX)',
    'Developer ID Application: Objective Development Software GmbH (MLZF7K7B5R)',
    'Developer ID Application: Objective-See, LLC (VBG97UB4TA)',
    'Developer ID Application: Opal Camera Inc (97Z3HJWCRT)',
    'Developer ID Application: Oracle America, Inc. (VB5E2TV963)',
    'Developer ID Application: reMarkable AS (4FFUD2H2F6)',
    'Developer ID Application: Snyk Limited (97QYW7LHSF)',
    'Developer ID Application: Sublime HQ Pty Ltd (Z6D26JE4Y4)',
    'Developer ID Application: TablePlus Inc (3X57WP8E8V)',
    'Developer ID Application: Tenable, Inc. (4B8J598M7U)',
    'Developer ID Application: Valve Corporation (MXGJJ98X76)',
    'Developer ID Application: Wireshark Foundation, Inc. (7Z6EMTD2C6)',
    'Software Signing'
  ) -- Don't spam alerts with repeated invocations of the same command-line
GROUP BY
  p.cmdline,
  p.cwd,
  p.euid;
