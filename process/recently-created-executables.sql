-- Programs who were recently written to disk, based on btime (macOS) or ctime (Linux)
--
-- NOTE: ctime

SELECT p.pid,
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
  ph.sha256 AS parent_sha256
FROM processes p
  LEFT JOIN file f ON p.path = f.path
  LEFT JOIN processes pp ON p.parent = pp.pid
  LEFT JOIN hash AS ch ON p.path = ch.path
  LEFT JOIN hash AS ph ON pp.path = ph.path
WHERE p.start_time > 0
  AND f.ctime > 0 -- Only process programs that had an inode modification within the last 3 minutes
  AND (p.start_time - MAX(f.ctime, f.btime)) < 180
  AND p.start_time >= MAX(f.ctime, f.ctime)
  AND NOT f.directory IN (
    "/Applications/Firefox.app/Contents/MacOS/plugin-container.app/Contents/MacOS",
    "/Applications/Grammarly Desktop.app/Contents/MacOS",
    "/Applications/Opal.app/Contents/Library/LaunchServices",
    "/Applications/Opal.app/Contents/MacOS",
    "/usr/local/kolide-k2/bin",
    "/Applications/Opal.app/Contents/XPCServices/OpalCameraDeviceService.xpc/Contents/MacOS",
    "/Applications/Signal.app/Contents/Frameworks/Signal Helper (GPU).app/Contents/MacOS",
    "/Applications/Signal.app/Contents/Frameworks/Signal Helper (Renderer).app/Contents/MacOS",
    "/Applications/Signal.app/Contents/Frameworks/Signal Helper.app/Contents/MacOS",
    "/Applications/Signal.app/Contents/MacOS",
    "/Applications/Slack.app/Contents/Frameworks/Slack Helper (GPU).app/Contents/MacOS",
    "/Applications/Slack.app/Contents/Frameworks/Slack Helper (Renderer).app/Contents/MacOS",
    "/Applications/Slack.app/Contents/Frameworks/Slack Helper.app/Contents/MacOS",
    "/Applications/Slack.app/Contents/MacOS",
    "/Applications/Spotify.app/Contents/Frameworks/Spotify Helper (GPU).app/Contents/MacOS",
    "/Applications/Spotify.app/Contents/Frameworks/Spotify Helper (Renderer).app/Contents/MacOS",
    "/Applications/Spotify.app/Contents/Frameworks/Spotify Helper.app/Contents/MacOS",
    "/Applications/Spotify.app/Contents/MacOS",
    "/Applications/Stream Deck.app/Contents/Frameworks/QtWebEngineCore.framework/Versions/5/Helpers/QtWebEngineProcess.app/Contents/MacOS",
    "/Applications/Stream Deck.app/Contents/MacOS",
    "/Library/Developer/CommandLineTools/usr/bin",
    "/Applications/Tailscale.app/Contents/MacOS",
    "/Applications/Tailscale.app/Contents/PlugIns/IPNExtension.appex/Contents/MacOS",
    "/Applications/Todoist.app/Contents/Frameworks/Todoist Helper (GPU).app/Contents/MacOS",
    "/Applications/Todoist.app/Contents/Frameworks/Todoist Helper (Renderer).app/Contents/MacOS",
    "/Applications/Todoist.app/Contents/Frameworks/Todoist Helper.app/Contents/MacOS",
    "/Applications/Todoist.app/Contents/MacOS",
    "/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS",
    "/Library/Apple/System/Library/PrivateFrameworks/MobileDevice.framework/Versions/A/Resources",
    "/Library/CoreMediaIO/Plug-Ins/DAL/OpalVirtualCamera.plugin/Contents/Resources",
    "/Library/Printers/Brother/Utilities/Server/LOGINserver.app/Contents/MacOS",
    "/Library/Printers/Brother/Utilities/Server/NETserver.app/Contents/MacOS",
    "/Library/Printers/Brother/Utilities/Server/USBAppControl.app/Contents/MacOS",
    "/Library/Printers/Brother/Utilities/Server/USBAppControl.app/Contents/MacOS",
    "/Library/Printers/Brother/Utilities/Server/USBserver.app/Contents/MacOS",
    "/Library/Printers/Brother/Utilities/Server/WorkflowAppControl.app/Contents/MacOS",
    "/Users/wolf/Library/Caches/company.thebrowser.Browser/org.sparkle-project.Sparkle/Launcher/FzhOGA60Z/Updater.app/Contents/MacOS"
  )
  AND NOT p.path IN (
    "",
    "/Library/DropboxHelperTools/Dropbox_u501/dbkextd",
    "/Library/PrivilegedHelperTools/com.adobe.acc.installer.v2",
    "/opt/google/chrome/chrome",
    "/usr/bin/containerd",
    "/usr/bin/dockerd",
    "/usr/bin/obs",
    "/Library/PrivilegedHelperTools/com.docker.vmnetd",
    "/usr/lib/at-spi-bus-launcher",
    "/usr/lib/at-spi2-registryd",
    "/usr/lib/fwupd/fwupd",
    "/usr/lib/slack/chrome_crashpad_handler",
    "/usr/lib/slack/slack",
    "/usr/lib/x86_64-linux-gnu/obs-plugins/obs-browser-page",
    "/usr/libexec/fwupd/fwupd",
    "/usr/lib/xf86-video-intel-backlight-helper",
    "/usr/libexec/sssd/sssd_kcm",
    "/usr/sbin/cupsd",
    "/usr/sbin/tailscaled"
  )
  AND NOT p.path LIKE "/Applications/%.app/%"
  AND NOT p.path LIKE "/home/%/%.test"
  AND NOT p.path LIKE "/home/%/bin/%"
  AND NOT p.path LIKE "/home/%/terraform-provider-%"
  AND NOT p.path LIKE "/Library/Apple/System/%"
  AND NOT p.path LIKE "/Library/Application Support/Adobe/Adobe Desktop Common/%"
  AND NOT p.path LIKE "/Library/Application Support/Logitech.localized/%"
  AND NOT p.path LIKE "/nix/store/%/bin/%"
  AND NOT p.path LIKE "/opt/homebrew/bin/%"
  AND NOT p.path LIKE "/opt/homebrew/Cellar/%"
  AND NOT p.path LIKE "/private/tmp/%/Creative Cloud Installer.app/Contents/MacOS/Install"
  AND NOT p.path LIKE "/private/tmp/go-build%"
  AND NOT p.path LIKE "/private/tmp/nix-build-%"
  AND NOT p.path LIKE "/private/var/db/com.apple.xpc.roleaccountd.staging/%"
  AND NOT p.path LIKE "/private/var/folders/%/bin/%"
  AND NOT p.path LIKE "/private/var/folders/%/go-build%"
  AND NOT p.path LIKE "/private/var/folders/%/GoLand/%"
  AND NOT p.path LIKE "/Users/%/%.test"
  AND NOT p.path LIKE "/Users/%/bin/%"
  AND NOT p.path LIKE "/Users/%/code/%"
  AND NOT p.path LIKE "/Users/%/Library/Application Support/%/Contents/MacOS/%"
  AND NOT p.path LIKE "/Users/%/Library/Application Support/iTerm2/iTermServer-%"
  AND NOT p.path LIKE "/Users/%/Library/Caches/%/Contents/MacOS/%"
  AND NOT p.path LIKE "/Users/%/Library/Google/%.bundle/Contents/Helpers/%"
  AND NOT p.path LIKE "/Users/%/Library/Mobile Documents/%/Contents/Frameworks%"
  AND NOT p.path LIKE "/Users/%/terraform-provider-%"
  AND NOT p.path LIKE "/usr/local/bin/%"
  AND NOT p.path LIKE "/usr/local/Cellar/%"
  AND NOT p.path LIKE "/usr/local/kolide-k2/bin/osqueryd-updates/%/osqueryd"
  AND NOT p.path LIKE "%-go-build%"
  AND NOT p.path LIKE "%/.vscode/extensions/%"
  AND NOT p.path LIKE "%/Library/Application Support/com.elgato.StreamDeck%" -- Known parent processes, typically GUI shells and updaters
  AND NOT pp.path IN ("/usr/bin/gnome-shell") -- Filter out developers working on their own code
  AND NOT (
    (
      p.path LIKE "/Users/%"
      OR p.path LIKE "/home/%"
    )
    AND p.uid > 499
    AND f.ctime = f.mtime
    AND f.uid = p.uid
    AND p.cmdline LIKE "./%"
  )
GROUP BY p.pid