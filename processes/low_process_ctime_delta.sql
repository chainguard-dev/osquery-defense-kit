SELECT f.path, f.ctime, p.start_time, (p.start_time - f.ctime) AS delta
FROM processes p
JOIN file f ON p.path = f.path
WHERE p.start_time > 0
AND delta < 300
AND delta > 0
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
AND NOT p.path LIKE "/Library/Apple/System/%"
AND NOT p.path LIKE "/private/var/db/com.apple.xpc.roleaccountd.staging/%"
AND NOT p.path LIKE "/Library/Apple/System/Library/%"
AND NOT p.path LIKE "%-go-build%"
AND NOT p.path LIKE "%/Library/Application Support/com.elgato.StreamDeck%"
AND NOT p.path LIKE "%/.vscode/extensions/%"