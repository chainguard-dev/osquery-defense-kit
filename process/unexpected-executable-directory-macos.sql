SELECT
  p.pid,
  p.name,
  p.path,
  p.euid,
  p.gid,
  f.ctime,
  f.directory AS dirname,
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
  LEFT JOIN processes pp ON p.parent = pp.pid
  LEFT JOIN signature ON p.path = signature.path
  -- NOTE: Everything after this is shared with process_events/unexpected-executable-directory-events
WHERE
  dirname NOT IN (
    "/bin",
    "/Library/DropboxHelperTools/Dropbox_u501",
    "/Library/Google/GoogleSoftwareUpdate/GoogleSoftwareUpdate.bundle/Contents/Helpers/GoogleSoftwareUpdateAgent.app/Contents/MacOS",
    "/Library/Printers/DYMO/Utilities",
    "/Library/PrivilegedHelperTools",
    "/sbin",
    "/usr/bin",
    "/usr/lib",
    "/usr/lib/bluetooth",
    "/usr/lib/cups/notifier",
    "/usr/lib/fwupd",
    "/usr/lib/ibus",
    "/opt/X11/bin",
    "/opt/X11/libexec",
    "/usr/libexec/AssetCache",
    "/usr/libexec",
    "/usr/libexec/ApplicationFirewall",
    "/usr/libexec/rosetta",
    "/usr/sbin",
    "/opt/usr/bin",
    "/usr/share/code",
    "/usr/share/teams/resources/app.asar.unpacked/node_modules/slimcore/bin"
  )
  AND dirname NOT LIKE "/Applications/%.app/%"
  AND dirname NOT LIKE "/Applications/Utilities/Adobe Creative Cloud/%"
  AND dirname NOT LIKE "/Library/%/%.bundle/Contents/Helpers"
  AND dirname NOT LIKE "/Library/%/Resources/%/Contents/MacOS"
  AND dirname NOT LIKE "/Library/%/sbin" -- Nessus
  AND dirname NOT LIKE "/Library/Apple/System/Library%"
  AND dirname NOT LIKE "/Library/Application Support/%/Contents/MacOS"
  AND dirname NOT LIKE "/Library/Application Support/Adobe/%"
  AND dirname NOT LIKE "/Library/Audio/Plug-Ins/%/Contents/MacOS"
  AND dirname NOT LIKE "/Library/CoreMediaIO/Plug-Ins/%"
  AND dirname NOT LIKE "/Library/Developer/%"
  AND dirname NOT LIKE "/Library/Developer/CommandLineTools/Library/%"
  AND dirname NOT LIKE "/Library/Internet Plug-Ins/%/Contents/MacOS"
  AND dirname NOT LIKE "/Library/Java/JavaVirtualMachines/%"
  AND dirname NOT LIKE "/Library/Printers/%.app/Contents/MacOS"
  AND dirname NOT LIKE "/Library/PrivilegedHelperTools/com.%"
  AND dirname NOT LIKE "/Library/SystemExtensions/%"
  AND dirname NOT LIKE "/nix/store/%"
  AND dirname NOT LIKE "/opt/homebrew/Cellar/%/bin"
  AND dirname NOT LIKE "/opt/homebrew/Cellar/%/libexec"
  AND dirname NOT LIKE "/opt/homebrew/Cellar/%/libexec/%"
  AND dirname NOT LIKE "/opt/homebrew/Cellar/%/Contents/MacOS"
  AND dirname NOT LIKE "/private/tmp/%.app/Contents/MacOS"
  AND dirname NOT LIKE "/private/tmp/go-build%/exe"
  AND dirname NOT LIKE "/private/tmp/nix-build-%"
  AND dirname NOT LIKE "/private/tmp/PKInstallSandbox.%/Scripts/com.microsoft.OneDrive.%"
  AND dirname NOT LIKE "/private/var/db/com.apple.xpc.roleaccountd.staging/%.xpc/Contents/MacOS"
  AND dirname NOT LIKE "/private/var/folders/%/bin"
  AND dirname NOT LIKE "/private/var/folders/%/Contents/%"
  AND dirname NOT LIKE "/private/var/folders/%/go-build%"
  AND dirname NOT LIKE "/private/var/folders/%/GoLand"
  AND dirname NOT LIKE "/System/%"
  AND dirname NOT LIKE "/Users/%"
  AND dirname NOT LIKE "/usr/libexec/%"
  AND dirname NOT LIKE "/usr/local/%"
 AND NOT (
    dirname LIKE "/private/var/%"
    AND p.name LIKE "pulumi-go.%"
  ) -- Chrome executes patches from /tmp :(
  AND NOT (
    dirname LIKE "/private/tmp/%"
    AND p.name = "goobspatch"
  )
