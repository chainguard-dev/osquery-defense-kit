-- Programs who were recently added to disk, based on btime/ctime
--
-- false-positives:
--   * many
--
-- tags: transient process state often
-- platform: darwin
SELECT
  p.pid,
  p.path,
  p.name,
  p.cmdline,
  p.cwd,
  p.euid,
  p.parent,
  f.directory,
  f.ctime,
  f.btime,
  f.mtime,
  p.start_time,
  pp.path AS parent_path,
  pp.name AS parent_name,
  pp.cmdline AS parent_cmdline,
  pp.cwd AS parent_cwd,
  pp.euid AS parent_euid,
  ch.sha256 AS child_sha256,
  ph.sha256 AS parent_sha256,
  signature.authority,
  signature.identifier
FROM
  processes p
  LEFT JOIN file f ON p.path = f.path
  LEFT JOIN processes pp ON p.parent = pp.pid
  LEFT JOIN hash AS ch ON p.path = ch.path
  LEFT JOIN hash AS ph ON pp.path = ph.path
  LEFT JOIN signature ON p.path = signature.path
WHERE
  p.start_time > 0
  AND f.ctime > 0 -- Only process programs that had an inode modification within the last 3 minutes
  AND (p.start_time - MAX(f.ctime, f.btime)) < 180
  AND p.start_time >= MAX(f.ctime, f.ctime)
  AND signature.authority NOT IN (
    'Apple Mac OS Application Signing',
    'Developer ID Application: Adobe Inc. (JQ525L2MZD)',
    'Developer ID Application: Brave Software, Inc. (KL8N8XSYF4)',
    'Developer ID Application: Brother Industries, LTD. (5HCL85FLGW)',
    'Developer ID Application: Bryan Jones (49EYHPJ4Q3)',
    'Developer ID Application: CodeWeavers Inc. (9C6B7X7Z8E)',
    'Developer ID Application: Corsair Memory, Inc. (Y93VXCB8Q5)',
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
    'Developer ID Application: Kolide Inc (YZ3EM74M78)',
    'Developer ID Application: Logitech Inc. (QED4VVPZWA)',
    'Developer ID Application: Michael Jones (YD6LEYT6WZ)',
    'Developer ID Application: Opal Camera Inc (97Z3HJWCRT)',
    'Developer ID Application: OSQUERY A Series of LF Projects, LLC (3522FA9PXF)',
    'Developer ID Application: RescueTime, Inc (FSY4RB8H39)',
    'Developer ID Application: Seiko Epson Corporation (TXAEAV5RN4)',
    'Developer ID Application: Yubico Limited (LQA3CS5MM7)',
    'Developer ID Application: Zoom Video Communications, Inc. (BJ4HAAB9B3)',
    'Software Signing'
  )
  AND NOT p.path LIKE '/Applications/%.app/%'
  AND NOT p.path LIKE '%-go-build%'
  AND NOT p.path LIKE '/Library/Apple/System/%'
  AND NOT p.path LIKE '/Library/Application Support/Adobe/Adobe Desktop Common/%'
  AND NOT p.path LIKE '%/Library/Application Support/com.elgato.StreamDeck%' -- Known parent processes, typically GUI shells and updaters
  AND NOT p.path LIKE '/Library/Application Support/Logitech.localized/%'
  AND NOT p.path LIKE '/nix/store/%/bin/%'
  AND NOT p.path LIKE '/opt/homebrew/bin/%'
  AND NOT p.path LIKE '/opt/homebrew/Cellar/%'
  AND NOT p.path LIKE '/private/tmp/%/Creative Cloud Installer.app/Contents/MacOS/Install'
  AND NOT p.path LIKE '/private/tmp/go-build%'
  AND NOT p.path LIKE '/private/tmp/nix-build-%'
  AND NOT p.path LIKE '/private/var/db/com.apple.xpc.roleaccountd.staging/%'
  AND NOT p.path LIKE '/private/var/folders/%/bin/%'
  AND NOT p.path LIKE '/private/var/folders/%/go-build%'
  AND NOT p.path LIKE '/private/var/folders/%/T/download/ARMDCHammer'
  AND NOT p.path LIKE '/private/var/folders/%/GoLand/%'
  AND NOT p.path LIKE '/private/var/folders/%/T/pulumi-go.%'
  AND NOT p.path LIKE '/Users/%/bin/%'
  AND NOT p.path LIKE '/Users/%/code/%'
  AND NOT p.path LIKE '/Users/%/src/%'
  AND NOT p.path LIKE '/Users/%/Library/Application Support/%/Contents/MacOS/%'
  AND NOT p.path LIKE '/Users/%/Library/Application Support/iTerm2/iTermServer-%'
  AND NOT p.path LIKE '/Users/%/Library/Caches/%/Contents/MacOS/%'
  AND NOT p.path LIKE '/Users/%/Library/Google/%.bundle/Contents/Helpers/%'
  AND NOT p.path LIKE '/Users/%/Library/Mobile Documents/%/Contents/Frameworks%'
  AND NOT p.path LIKE '/Users/%/terraform-provider-%'
  AND NOT p.path LIKE '/Users/%/%.test'
  AND NOT p.path LIKE '/usr/local/bin/%'
  AND NOT p.path LIKE '/usr/local/Cellar/%'
  AND NOT p.path LIKE '/usr/local/kolide-k2/bin/osqueryd-updates/%/osqueryd'
  AND NOT p.path LIKE '%/.vscode/extensions/%'
  AND NOT p.path LIKE '/Users/%/Library/Caches/snyk/%/snyk-macos'
  AND NOT (
    p.path LIKE '/Users/%'
    AND p.uid > 499
    AND f.ctime = f.mtime
    AND f.uid = p.uid
    AND p.cmdline LIKE './%'
  )
GROUP BY
  p.pid
