-- Unexpected launchd scripts that use the 'program_arguments' field
--
-- references:
--   * https://attack.mitre.org/techniques/T1543/004/ (Create or Modify System Process: Launch Daemon)
--
-- false positives:
--   * Software by new vendors which have not yet been added to the allow list
--
-- tags: persistent filesystem state
-- platform: darwin
SELECT
  l.label,
  l.name,
  l.path,
  TRIM(REGEX_SPLIT (l.program_arguments, ' -', 0)) AS program_path,
  l.program_arguments,
  l.keep_alive,
  signature.authority AS program_authority,
  hash.sha256
FROM
  launchd l
  LEFT JOIN signature ON program_path = signature.path
  LEFT JOIN hash ON program_path = hash.path
WHERE
  (
    run_at_load = 1
    OR keep_alive = 1
  )
  AND (
    program IS NULL
    OR program = ''
  )
  AND l.path NOT LIKE '/System/%'
  AND l.path NOT LIKE '/Library/Apple/System/%'
  AND program_authority NOT IN (
    'Developer ID Application: Adobe Inc. (JQ525L2MZD)',
    'Developer ID Application: Canonical Group Limited (X4QN7LTP59)',
    'Developer ID Application: Canva Pty Ltd (5HD2ARTBFS)',
    'Developer ID Application: Corsair Memory, Inc. (Y93VXCB8Q5)',
    'Developer ID Application: Foxit Corporation (8GN47HTP75)',
    'Developer ID Application: Fumihiko Takayama (G43BCU2T37)',
    'Developer ID Application: Google LLC (EQHXZ8M8AV)',
    'Developer ID Application: Google, Inc. (EQHXZ8M8AV)',
    'Developer ID Application: Hercules Labs Inc. (B8PC799ZGU)',
    'Developer ID Application: JetBrains s.r.o. (2ZEFAR8TH3)',
    'Developer ID Application: OPENVPN TECHNOLOGIES, INC. (ACV7L3WCD8)',
    'Developer ID Application: Keybase, Inc. (99229SGT5K)',
    'Developer ID Application: Kolide Inc (YZ3EM74M78)',
    'Developer ID Application: Kolide, Inc (X98UFR7HA3)',
    'Developer ID Application: Krisp Technologies, Inc. (U5R26XM5Z2)',
    'Developer ID Application: Logitech Inc. (QED4VVPZWA)',
    'Developer ID Application: MacPaw Inc. (S8EX82NJP6)',
    'Developer ID Application: Mersive Technologies (63B5A5WDNG)',
    'Developer ID Application: Microsoft Corporation (UBF8T346G9)',
    'Developer ID Application: OSQUERY A Series of LF Projects, LLC (3522FA9PXF)',
    'Developer ID Application: Objective-See, LLC (VBG97UB4TA)',
    'Developer ID Application: PFU LIMITED (XW4U7W2E9L)', -- Fujitsu
    'Developer ID Application: Paragon Software GmbH (LSJ6YVK468)',
    'Developer ID Application: Private Internet Access, Inc. (5357M5NW9W)',
    'Developer ID Application: Proton Technologies AG (6UN54H93QT)',
    'Developer ID Application: Sanford, L.P. (N3S6676K3E)', -- DYMO
    'Developer ID Application: Seiko Epson Corporation (TXAEAV5RN4)',
    'Developer ID Application: Tenable, Inc. (4B8J598M7U)',
    'Developer ID Application: X-Rite, Incorporated (2K7GT73B4R)',
    'Software Signing', -- Apple
    'yabai-cert'
  )
  AND program_arguments NOT IN (
    '/Applications/Stream Deck.app/Contents/MacOS/Stream Deck --runinbk',
    '/Library/Application Support/WirelessAutoImport/WirelessImporterDaemon',
    '/Library/Application Support/Sony Application Launcher/SonyAutoLauncher.app/Contents/MacOS/SonyAutoLauncher',
    '/opt/homebrew/opt/dnsmasq/sbin/dnsmasq --keep-in-foreground -C /opt/homebrew/etc/dnsmasq.conf -7 /opt/homebrew/etc/dnsmasq.d,*.conf',
    '/opt/homebrew/opt/jenkins/bin/jenkins --httpListenAddress=127.0.0.1 --httpPort=8080',
    '/opt/homebrew/opt/mariadb/bin/mysqld_safe',
    '/Applications/Tunnelblick.app/Contents/Resources/launchAtLogin.sh',
    '/opt/homebrew/bin/gitsign-credential-cache',
    '/opt/homebrew/opt/pueue/bin/pueued --verbose',
    '/opt/homebrew/opt/nginx/bin/nginx -g daemon off;',
    '/opt/homebrew/opt/skhd/bin/skhd',
    '/opt/homebrew/opt/tailscale/bin/tailscaled',
    '/opt/homebrew/opt/yubikey-agent/bin/yubikey-agent -l /opt/homebrew/var/run/yubikey-agent.sock',
    '/usr/local/MacGPG2/libexec/fixGpgHome'
  )
  AND program_arguments NOT LIKE '/opt/homebrew/opt/mongodb-community%/bin/mongod --config /opt/homebrew/etc/mongod.conf'
  AND program_arguments NOT LIKE '/Users/%/Library/Application Support/com.grammarly.ProjectLlama/Scripts/Grammarly Uninstaller'
  AND program_arguments NOT LIKE '/Users/%/Library/Application Support/com.grammarly.ProjectLlama/Scripts/post-uninstall.sh'
  AND program_arguments NOT LIKE '%/mysqld_safe --datadir=%'
  AND program_arguments NOT LIKE '/opt/homebrew/opt/socket_vmnet/bin/socket_vmnet --vmnet-gateway=% /opt/homebrew/var/run/socket_vmnet'
