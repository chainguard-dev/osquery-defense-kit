-- Returns a list of recently written files
--
-- tags: postmortem
-- platform: posix
-- interval: 3600
SELECT *
FROM file
WHERE (
        path LIKE "/var/tmp/%"
        OR path LIKE "/var/tmp/%/%"
        OR path LIKE "/Applications/%"
        OR path LIKE "/Applications/%/%"
        OR path LIKE "/home/%/%"
        OR path LIKE "/home/%/.%/%"
        OR path LIKE "/home/%/.%/%/%"
        OR path LIKE "/home/%/.config/%"
        OR path LIKE "/home/%/.config/%/%"
        OR path LIKE "/Library/%/%"
        OR path LIKE "/Library/.%"
        OR path LIKE "/Library/Application Support/%"
        OR path LIKE "/Library/Application Support/.%"
        OR path LIKE "/tmp/%"
        OR path LIKE "/tmp/%/%"
        OR path LIKE "/tmp/.%/%%"
        OR path LIKE "/Users/%/%"
        OR path LIKE "/Users/%/%/%"
        OR path LIKE "/Users/%/.%/%"
        OR path LIKE "/Users/%/.%/%/%"
        OR path LIKE "/Users/Library/%"
        OR path LIKE "/Users/Library/%/%"
        OR path LIKE "/Users/Library/.%"
        OR path LIKE "/Users/Library/Application Support/%"
        OR path LIKE "/Users/Library/Application Support/%/%"
        OR path LIKE "/Users/Library/Application Support/.%"
        OR path LIKE "/var/%"
        OR path LIKE "/var/%/%"
    )
    AND (
        mtime > (strftime('%s', 'now') -3600)
        OR (
            atime > (strftime('%s', 'now') -3600)
            AND file.type = "regular"
        )
        OR ctime > (strftime('%s', 'now') -3600)
        OR btime > (strftime('%s', 'now') -3600)
    )
    AND NOT path LIKE "%/../%"
GROUP BY inode;