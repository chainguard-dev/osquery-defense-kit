SELECT p.pid,
   p.path,
   p.name,
   p.cmdline,
   p.cwd,
   p.euid,
   p.parent,
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
   AND (p.start_time - f.ctime) < 180
   AND (p.start_time - f.ctime) > 0
   AND NOT p.path IN (
      '/Library/Application Support/Logitech.localized/Logitech Presentation.localized/Onboarding.app/Contents/MacOS/Onboarding',
      '/opt/google/chrome/chrome',
      '/usr/bin/containerd',
      '/usr/bin/obs',
      '/usr/lib/x86_64-linux-gnu/obs-plugins/obs-browser-page',
      '/usr/libexec/fwupd/fwupd',
      '/usr/libexec/sssd/sssd_kcm',
      '/usr/sbin/cupsd',
      '/usr/sbin/tailscaled'
   )
   AND NOT p.path LIKE "/Applications/%.app/%"
   AND NOT p.path LIKE "/private/var/folders/%/bin/istioctl"
   AND NOT p.path LIKE "/usr/local/kolide-k2/bin/osqueryd-updates/%/osqueryd"
   AND NOT p.path LIKE "/private/var/folders/%/go-build%/exe/%"
   AND NOT p.path LIKE "/nix/store/%/bin/%"
   AND NOT p.path LIKE "/Library/Apple/System/%"
   AND NOT p.path LIKE "/private/var/db/com.apple.xpc.roleaccountd.staging/%"
   AND NOT p.path LIKE "/Library/Apple/System/Library/%"
   AND NOT p.path LIKE "%-go-build%"
   AND NOT p.path LIKE "/home/%/go/bin"
   AND NOT p.path LIKE "/Users/%/go/bin"
   AND NOT p.path LIKE "%/Library/Application Support/com.elgato.StreamDeck%"
   AND NOT p.path LIKE "%/.vscode/extensions/%"