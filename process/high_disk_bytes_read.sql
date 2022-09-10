SELECT *, (strftime('%s', 'now') - start_time) AS age, disk_bytes_read / (strftime('%s', 'now') - start_time) AS bytes_per_second
FROM processes
WHERE bytes_per_second > 1750000
AND age > 180
AND NOT (name IN ('slack', 'firefox', 'GoogleSoftwareUpdateAgent', 'zsh', 'bash', 'ykman-gui', 'nautilus'))
AND NOT (name='aned' AND cmdline='/usr/libexec/aned' AND parent=1)
AND NOT (name='bindfs' AND cmdline LIKE 'bindfs -f -o fsname=%')
AND NOT (name='chrome' AND path='/opt/google/chrome/chrome')
AND NOT (name='com.apple.MobileSoftwareUpdate.UpdateBrainService' AND path LIKE '/private/var/db/com.apple.xpc.roleaccountd.staging/com.apple.MobileSoftwareUpdate.UpdateBrainService.%.xpc/Contents/MacOS/com.apple.MobileSoftwareUpdate.UpdateBrainService')
AND NOT (name='FindMy' AND path='/System/Applications/FindMy.app/Contents/MacOS/FindMy')
AND NOT (name='go' AND cmdline LIKE 'go run %')
AND NOT (name='gopls' AND path LIKE '/home/%/bin/gopls')
AND NOT (name='gopls' AND path LIKE '/home/%/gopls/gopls')
AND NOT (name='gopls' AND path LIKE '/Users/%/bin/gopls')
AND NOT (name='gopls' AND path LIKE '/Users/%/gopls/gopls')
AND NOT (name='ruby' AND cmdline LIKE '%brew.rb upgrade')
AND NOT (name='kernel_task' AND path='' AND parent IN (0,1) AND on_disk=-1)
AND NOT (name='launcher' AND path='/usr/local/kolide-k2/bin/launcher-updates/1659471464/launcher')
AND NOT (name='logd' AND cmdline='/usr/libexec/logd' AND parent=1)
AND NOT (name='LogiFacecamService')
AND NOT (name='node' AND cwd LIKE '%/console-ui/app')
AND NOT (name='osqueryd' AND path LIKE '/usr/local/kolide-k2/bin/osqueryd-updates/%/osqueryd')
AND NOT (name='packagekitd' AND path='/usr/libexec/packagekitd')
AND NOT (name='PerfPowerServices' AND path='/usr/libexec/PerfPowerServices')
AND NOT (name='signpost_reporter' AND cmdline='/usr/libexec/signpost_reporter' AND parent=1)
AND NOT (name='snapd' AND path='/usr/lib/snaptd/snaptd')
AND NOT (name='spindump' AND path='/usr/sbin/spindump')
AND NOT (name='syspolicyd' AND path='/usr/libexec/syspolicyd' AND parent=1)
AND NOT (name='systemd-udevd' AND path='/usr/bin/udevadm')
AND NOT (name='systemd' AND path='/usr/lib/systemd/systemd')
AND NOT (name='systemstats' AND path='/usr/sbin/systemstats')
AND NOT (path='/usr/bin/gnome-shell')
AND NOT (name='terraform-ls' AND cmdline LIKE 'terraform-ls serve%')
AND NOT (path LIKE '/home/%/Apps/PhpStorm%/jbr/bin/java')
AND path NOT LIKE '/Applications/%.app/Contents/%'
AND path NOT LIKE '/System/Library/%'
AND path NOT LIKE '/System/Applications/%'
AND path NOT LIKE '/Library/Apple/System/Library/%'