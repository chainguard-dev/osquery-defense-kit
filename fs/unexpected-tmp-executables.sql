SELECT path, uid, gid, mode, strftime('%s', 'now') - ctime AS mtime_age, FROM file WHERE
(path LIKE "/tmp/%%" OR path LIKE "/var/tmp/%%")
AND type = "regular"
AND mode LIKE "07%"
AND path NOT LIKE "%go-build%"
AND path NOT LIKE "%/bin/%-gen"
AND path NOT LIKE "%/bin/%"
AND path NOT LIKE "%/ko/%"
AND path NOT LIKE "%/CCLBS/%"
AND PATH NOT LIKE "%/tmp/epdf%"
AND PATH NOT LIKE "%/pdf-tools/%"
AND PATH NOT LIKE "/tmp/%.sh"
AND PATH NOT LIKE "/tmp/terraformer/%"
AND PATH NOT LIKE "/tmp/checkout/%"
AND PATH NOT LIKE "/tmp/guile-%/guile-%"
AND PATH NOT LIKE "/tmp/com.apple.installer%"
-- Nix
AND NOT (directory LIKE "/tmp/tmp%" AND gid=0 AND uid> 300 AND uid< 350)
-- Don't alert if it's only on disk for a moment
AND NOT (directory LIKE "/tmp/%" AND mtime_age < 60)