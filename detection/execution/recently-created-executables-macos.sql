-- Programs who were recently added to disk, based on btime/ctime
--
-- false-positives:
--   * many
--
-- tags: transient process state often
-- platform: darwin
SELECT
  f.ctime,
  f.btime,
  f.mtime,
  p0.start_time,
  -- Child
  p0.pid AS p0_pid,
  p0.path AS p0_path,
  s.authority AS p0_sauth,
  s.identifier AS p0_sid,
  p0.name AS p0_name,
  p0.cmdline AS p0_cmd,
  p0.cwd AS p0_cwd,
  p0.euid AS p0_euid,
  p0_hash.sha256 AS p0_sha256,
  -- Parent
  p0.parent AS p1_pid,
  p1.path AS p1_path,
  p1.name AS p1_name,
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
  LEFT JOIN signature s ON p0.path = s.path
  LEFT JOIN file f ON p0.path = f.path
  LEFT JOIN hash p0_hash ON p0.path = p0_hash.path
  LEFT JOIN processes p1 ON p0.parent = p1.pid
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
      start_time > 0
      AND start_time > (strftime('%s', 'now') - 7200)
      AND pid > 0
      AND path != ""
      AND NOT path LIKE '/Applications/%'
      AND NOT path LIKE '%-go-build%'
      AND NOT path LIKE '/Library/Apple/%'
      AND NOT path LIKE '/Library/Application Support/Adobe/Adobe Desktop Common/%'
      AND NOT path LIKE '%/Library/Application Support/com.elgato.StreamDeck%'
      AND NOT path LIKE '/Library/Application Support/Logitech.localized/%'
      AND NOT path LIKE '/nix/store/%'
      AND NOT path LIKE '/opt/homebrew/%'
      AND NOT path LIKE '/private/tmp/%/Creative Cloud Installer.app/Contents/MacOS/Install'
      AND NOT path LIKE '/private/tmp/go-%'
      AND NOT path LIKE '/private/tmp/nix-build-%'
      AND NOT path LIKE '/private/var/db/com.apple.xpc.roleaccountd.staging/%'
      AND NOT path LIKE '/private/var/folders/%/bin/%'
      AND NOT path LIKE '/private/var/folders/%/d/Wrapper/%.app/%'
      AND NOT path LIKE '/private/var/folders/%/go-build%'
      AND NOT path LIKE '/private/var/folders/%/GoLand/%'
      AND NOT path LIKE '/private/var/folders/%/T/download/ARMDCHammer'
      AND NOT path LIKE '/private/var/folders/%/T/pulumi-go.%'
      AND NOT path LIKE '/System/%'
      AND NOT path LIKE '/Users/%/Applications (Parallels)/%/Contents/MacOS/WinAppHelper'
      AND NOT path LIKE '/Users/%/bin/%'
      AND NOT path LIKE '/Users/%/code/%'
      AND NOT path LIKE '/Users/%/dev/%'
      AND NOT path LIKE '/Users/%/Library/Application Support/%/Contents/MacOS/%'
      AND NOT path LIKE '/Users/%/Library/Application Support/iTerm2/iTermServer-%'
      AND NOT path LIKE '/Users/%/Library/Caches/%/Contents/MacOS/%'
      AND NOT path LIKE '/Users/%/Library/Caches/snyk/%/snyk-macos'
      AND NOT path LIKE '/Users/%/Library/Developer/Xcode/UserData/Previews/Simulator Devices/%/data/Containers/Bundle/Application/%'
      AND NOT path LIKE '/Users/%/Library/Google/%.bundle/Contents/Helpers/%'
      AND NOT path LIKE '/Users/%/Library/Mobile Documents/%/Contents/Frameworks%'
      AND NOT path LIKE '/Users/%/.local/share/nvim/mason/packages/%'
      AND NOT path LIKE '/Users/%/node_modules/.bin/%'
      AND NOT path LIKE '/Users/%/node_modules/.pnpm/%'
      AND NOT path LIKE '/Users/%/Parallels/%/Contents/MacOS/WinAppHelper'
      AND NOT path LIKE '/Users/%/src/%'
      AND NOT path LIKE '/Users/%/terraform-provider-%'
      AND NOT path LIKE '/Users/%/%.test'
      AND NOT path LIKE '/usr/local/Cellar/%'
      AND NOT path LIKE '/usr/local/kolide-k2/%'
      AND NOT path LIKE '%/.vscode/extensions/%'
    GROUP BY
      path
  )
  AND (p0.start_time - MAX(f.ctime, f.btime)) < 120
  AND f.ctime > 0
  AND s.authority NOT IN (
    'Apple iPhone OS Application Signing',
    'Apple Mac OS Application Signing',
    'Developer ID Application: Adobe Inc. (JQ525L2MZD)',
    'Developer ID Application: Brave Software, Inc. (KL8N8XSYF4)',
    'Developer ID Application: Brother Industries, LTD. (5HCL85FLGW)',
    'Developer ID Application: Bryan Jones (49EYHPJ4Q3)',
    'Developer ID Application: Canon Inc. (XE2XNRRXZ5)',
    'Developer ID Application: CodeWeavers Inc. (9C6B7X7Z8E)',
    'Developer ID Application: Corsair Memory, Inc. (Y93VXCB8Q5)',
    'Developer ID Application: Denver Technologies, Inc (2BBY89MBSN)',
    'Developer ID Application: Docker Inc (9BNSXJN65R)',
    'Developer ID Application: Dropbox, Inc. (G7HH3F8CAK)',
    'Developer ID Application: Emmanouil Konstantinidis (3YP8SXP3BF)',
    'Developer ID Application: Galvanix (5BRAQAFB8B)',
    'Developer ID Application: General Arcade (Pte. Ltd.) (S8JLSG5ES7)',
    'Developer ID Application: GEORGE NACHMAN (H7V7XYVQ7D)',
    'Developer ID Application: GitHub (VEKTX9H2N7)',
    'Developer ID Application: Google LLC (EQHXZ8M8AV)',
    'Developer ID Application: GPGTools GmbH (PKV8ZPD836)',
    'Developer ID Application: JetBrains s.r.o. (2ZEFAR8TH3)',
    'Developer ID Application: Kandji, Inc. (P3FGV63VK7)',
    'Developer ID Application: Kolide Inc (YZ3EM74M78)',
    'Developer ID Application: Logitech Inc. (QED4VVPZWA)',
    'Developer ID Application: Michael Jones (YD6LEYT6WZ)',
    'Developer ID Application: Microsoft Corporation (UBF8T346G9)',
    'Developer ID Application: Objective Development Software GmbH (MLZF7K7B5R)',
    'Developer ID Application: Objective-See, LLC (VBG97UB4TA)',
    'Developer ID Application: Opal Camera Inc (97Z3HJWCRT)',
    'Developer ID Application: OSQUERY A Series of LF Projects, LLC (3522FA9PXF)',
    'Developer ID Application: Parallels International GmbH (4C6364ACXT)',
    'Developer ID Application: RescueTime, Inc (FSY4RB8H39)',
    'Developer ID Application: Seiko Epson Corporation (TXAEAV5RN4)',
    'Developer ID Application: Sublime HQ Pty Ltd (Z6D26JE4Y4)',
    'Developer ID Application: SUSE LLC (2Q6FHJR3H3)',
    'Developer ID Application: Yubico Limited (LQA3CS5MM7)',
    'Developer ID Application: Zoom Video Communications, Inc. (BJ4HAAB9B3)',
    'Software Signing'
  )
  AND NOT (
    p0.path LIKE '/Users/%/__debug_bin'
    AND s.identifier = 'a.out'
  )
  AND NOT (
    p0.path LIKE '/Users/%'
    AND p0.uid > 499
    AND f.ctime = f.mtime
    AND f.uid = p0.uid
    AND p0.cmdline LIKE './%'
  )
  AND NOT (
    p0.path LIKE '/Users/%/Library/Printers/%/Contents/MacOS/PrinterProxy'
    AND s.identifier = 'com.apple.print.PrinterProxy'
    AND s.authority = ''
    AND p0.uid > 499
  )
GROUP BY
  p0.pid
