SELECT name,path,cmdline,on_disk,parent,start_time,disk_bytes_written,cwd,(strftime('%s', 'now') - start_time) AS age, disk_bytes_written / (strftime('%s', 'now') - start_time) AS bytes_per_second
FROM processes
WHERE bytes_per_second > 120000
AND age > 120
AND NOT (name='bindfs' AND cmdline LIKE 'bindfs -f -o fsname=%')
AND NOT (name='btrfs-transaction' AND on_disk=-1)
AND NOT (name LIKE "jbd%/dm-%" AND on_disk=-1)
AND NOT (name='chrome' AND path='/opt/google/chrome/chrome')
AND NOT (name='coreduetd' AND path='/usr/libexec/coreduetd')
AND NOT (name='gnome-shell' AND path='/usr/bin/gnome-shell')
AND NOT (name='kernel_task' AND path='' AND parent IN (0,1) AND on_disk=-1)
AND NOT (name='launchd' AND path='/sbin/launchd' aND parent=0)
AND NOT (name='logd' AND cmdline='/usr/libexec/logd' AND parent=1)
AND NOT (name='oahd' AND path='/usr/libexec/rosetta/oahd')
AND NOT (name='systemd' AND path='/usr/lib/systemd/systemd')
AND NOT name IN ('firefox','gopls')
AND path NOT LIKE '/Applications/%.app/Contents/%'
AND path NOT LIKE '/System/Applications/%'
AND path NOT LIKE '/System/Library/%'
