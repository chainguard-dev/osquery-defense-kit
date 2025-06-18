-- Unexpected crontab entries
--
-- references:
--   * https://attack.mitre.org/techniques/T1053/003/ (Scheduled Task/Job: Cron)
--
-- false positives:
--   * crontab entries added by the user
--
-- tags: persistent filesystem state
-- platform: posix
SELECT
  *
FROM
  crontab
WHERE
  command NOT LIKE '%/usr/lib/php/sessionclean%'
  AND command NOT LIKE '%anacron start%'
  AND command NOT LIKE '%clamscan%'
  AND command NOT LIKE '%e2scrub%'
  AND command NOT LIKE '%freshclam%'
  AND command NOT LIKE '%gcloud compute instances stop%'
  AND command NOT LIKE '%git commit%'
  AND command NOT LIKE '%rsync%'
  AND command NOT LIKE '%zfs-linux%'
  AND command NOT LIKE 'docker run amouat/jocko%'
  AND command NOT LIKE 'gsutil %'
  AND command NOT LIKE 'root [ -d "/run/systemd/system" ] || /usr/share/atop/atop%'
  AND command NOT LIKE 'root command -v debian-sa1%'
  AND command NOT LIKE 'root test -x /usr/bin/geoipupdate % && /usr/bin/geoipupdate'
  AND command NOT LIKE 'root%run-parts%'
  AND command NOT LIKE '/opt/homebrew/bin/%'
  AND command NOT IN (
    "ps -A | grep at.obdev.littlesnitch.networkextension | grep -v 'grep' | awk '{print $1}' | xargs kill",
    'root [ -d "/run/systemd/system" ] && systemctl restart atop',
    'root test -x /etc/cron.daily/popularity-contest && /etc/cron.daily/popularity-contest --crond',
    'timeout --kill-after=10 100 mbsync -q -a',
    '~/scripts/gmail-token-refresh.py',
    '~/.dotfiles/git_auto_commit.sh',
    'osascript -e "set volume with output muted"'
  )
