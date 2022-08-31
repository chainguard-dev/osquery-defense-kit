SELECT *,
(strftime('%s', 'now') - start_time) AS age,
disk_bytes_written / (strftime('%s', 'now') - start_time) AS bytes_per_second
FROM processes
WHERE bytes_per_second > 100000
AND age > 300
AND NOT (name = 'backupd' AND path = '/System/Library/CoreServices/backupd.bundle/Contents/Resources/backupd')
AND NOT (name = 'bindfs' AND cmdline LIKE "bindfs -f -o fsname=%")
AND NOT (name = 'Brave Browser Helper' AND path = '/Applications/Brave Browser.app/Contents/Frameworks/Brave Browser Framework.framework/Versions/97.1.34.80/Helpers/Brave Browser Helper.app/Contents/MacOS/Brave Browser Helper')
AND NOT (name = 'Brave Browser' AND path = '/Applications/Brave Browser.app/Contents/MacOS/Brave Browser')
AND NOT (name = 'cloudd' AND path = '/System/Library/PrivateFrameworks/CloudKitDaemon.framework/Support/cloudd')
AND NOT (name = 'com.apple.MobileSoftwareUpdate.UpdateBrainService' AND path LIKE '/private/var/db/com.apple.xpc.roleaccountd.staging/com.apple.MobileSoftwareUpdate.UpdateBrainService.%.xpc/Contents/MacOS/com.apple.MobileSoftwareUpdate.UpdateBrainService')
AND NOT (name = 'com.apple.Virtualization.VirtualMachine' AND path = '/System/Library/Frameworks/Virtualization.framework/Versions/A/XPCServices/com.apple.Virtualization.VirtualMachine.xpc/Contents/MacOS/com.apple.Virtualization.VirtualMachine')
AND NOT (name = 'com.docker.hyperkit' AND path = '/Applications/Docker.app/Contents/Resources/bin/com.docker.hyperkit')
AND NOT (name = 'Google Chrome Helper' AND path LIKE '/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/%/Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper')
AND NOT (name = 'Google Chrome' AND path = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome')
AND NOT (name = 'gopls' AND path LIKE '/home/%/bin/gopls')
AND NOT (name = 'gopls' AND path LIKE '/home/%/gopls/gopls')
AND NOT (name = 'gopls' AND path LIKE '/Users/%/bin/gopls')
AND NOT (name = 'gopls' AND path LIKE '/Users/%/code/bin/gopls')
AND NOT (name = 'gopls' AND path LIKE '/Users/%/gopls/gopls')
AND NOT (name = 'idea' AND path = '/Applications/IntelliJ IDEA.app/Contents/MacOS/idea')
AND NOT (name = 'kernel_task' AND path = '' AND parent IN (0,1) AND on_disk=-1)
AND NOT (name = 'launchd' AND path = '/sbin/launchd' aND parent=0)
AND NOT (name = 'logd' AND cmdline = '/usr/libexec/logd' AND parent=1)
AND NOT (name = 'mds_stores' AND path = '/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/Metadata.framework/Versions/A/Support/mds_stores')
AND NOT (name = 'oahd' AND path = '/usr/libexec/rosetta/oahd')
AND NOT (name = 'photolibraryd' AND path = '/System/Library/PrivateFrameworks/PhotoLibraryServices.framework/Versions/A/Support/photolibraryd')
AND NOT (name = 'qemu-system-aarch64' AND path = '/Applications/Docker.app/Contents/MacOS/qemu-system-aarch64')
AND NOT (name = 'suggestd' AND path = '/System/Library/PrivateFrameworks/CoreSuggestions.framework/Versions/A/Support/suggestd')