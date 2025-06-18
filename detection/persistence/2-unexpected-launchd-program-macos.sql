-- Unexpected launchd scripts that use the 'program' field
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
  l.program,
  l.program_arguments,
  l.keep_alive,
  signature.authority AS program_authority,
  signature.identifier AS program_identifier,
  hash.sha256
FROM
  launchd l
  LEFT JOIN signature ON l.program = signature.path
  LEFT JOIN hash ON l.path = hash.path
WHERE
  (
    run_at_load = 1
    OR keep_alive = 1
  )
  AND l.path NOT LIKE '/System/%'
  AND program IS NOT NULL
  AND program_authority NOT IN (
    'Developer ID Application: Adguard Software Limited (TC3Q7MAJXF)',
    'Developer ID Application: Adobe Inc. (JQ525L2MZD)',
    'Developer ID Application: Bitdefender SRL (GUNFMW623Y)',
    'Developer ID Application: Bjango Pty Ltd (Y93TK974AT)',
    'Developer ID Application: Canonical Group Limited (X4QN7LTP59)',
    'Developer ID Application: Creative Labs Pte. Ltd. (5Q3552844F)',
    'Developer ID Application: Docker Inc (9BNSXJN65R)',
    'Developer ID Application: EA Swiss Sarl (TSTV75T6Q5)',
    'Developer ID Application: Elasticsearch, Inc (2BT3HPN62Z)',
    'Developer ID Application: Expressco Services, LLC (TC292Y5427)', -- ExpressVPN, bleh.
    'Developer ID Application: Fortinet, Inc (AH4XFXJ7DK)',
    'Developer ID Application: Hercules Labs Inc. (B8PC799ZGU)',
    'Developer ID Application: Ilya Parniuk (ACC5R6RH47)',
    'Developer ID Application: iMobie Inc. (2QJGLWL8Y6)',
    'Developer ID Application: Jonathan Bullard (Z2SG5H3HC8)',
    'Developer ID Application: Kandji, Inc. (P3FGV63VK7)',
    'Developer ID Application: Logitech Inc. (QED4VVPZWA)',
    'Developer ID Application: Louis Pontoise (QXD7GW8FHY)',
    'Developer ID Application: Microsoft Corporation (UBF8T346G9)',
    'Developer ID Application: Nordvpn S.A. (W5W395V82Y)',
    'Developer ID Application: Objective Development Software GmbH (MLZF7K7B5R)',
    'Developer ID Application: Oracle America, Inc. (VB5E2TV963)',
    'Developer ID Application: PACE Anti-Piracy, Inc. (TFZ8226T6X)',
    'Developer ID Application: Rapid7 LLC (UL6CGN7MAL)',
    'Developer ID Application: Rogue Amoeba Software, Inc. (7266XEXAPM)',
    'Developer ID Application: Signify Netherlands B.V. (PREPN2W95S)',
    'Developer ID Application: TPZ Solucoes Digitais Ltda (X37R283V2T)',
    'Developer ID Application: Universal Audio (4KAC9AX6CG)',
    'Developer ID Application: Valve Corporation (MXGJJ98X76)',
    'Developer ID Application: Wireshark Foundation (7Z6EMTD2C6)',
    'Developer ID Application: Wireshark Foundation, Inc. (7Z6EMTD2C6)',
    'Developer ID Application: Y Soft Corporation, a.s. (3CPED8WGS9)',
    'Developer ID Application: Yufu Fan (S3YBM9ALKM)',
    'Developer ID Application: Zoom Video Communications, Inc. (BJ4HAAB9B3)',
    'Software Signing'
  )
  AND program NOT IN (
    '/usr/local/bin/warsaw/core',
    '/usr/local/MacGPG2/libexec/shutdown-gpg-agent'
  )
  -- Special case: Docker does not consistently sign their plist files (security fail)
  AND NOT (
    l.path = '/Library/LaunchDaemons/com.docker.socket.plist'
    AND program_authority = 'Software Signing'
    AND program_identifier IN ('com.apple.ln', 'com.apple.link')
    AND program_arguments LIKE '/bin/ln -s -f /Users/%/run/docker.sock /var/run/docker.sock'
  )
  AND NOT (
    l.path = '/Library/LaunchDaemons/com.docker.socket.plist'
    AND program_identifier = 'com.docker'
    AND program_authority = NULL
    AND program = '/Library/PrivilegedHelperTools/com.docker.socket'
  )
  AND NOT (
    l.path = '/Library/LaunchDaemons/com.docker.vmnetd.plist'
    AND program_identifier = 'com.docker.vmnetd'
    AND program_authority = NULL
    AND program = '/Library/PrivilegedHelperTools/com.docker.vmnetd'
  )
  AND NOT l.label IN ('org.nix-community.home.sops-nix','com.github.domt4.homebrew-autoupdate')
GROUP BY
  l.path
