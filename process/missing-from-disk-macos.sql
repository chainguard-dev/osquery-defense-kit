SELECT p.pid, p.path, p.parent, p.state, p.cwd, p.gid, p.uid, p.euid, p.cmdline AS cmd, p.cwd,
p.on_disk, p.state,  (strftime('%s', 'now') - p.start_time) AS age,
pp.on_disk AS parent_on_disk, pp.path AS parent_path, pp.cmdline AS parent_cmd, pp.cwd AS parent_cwd, hash.sha256 AS parent_sha256
FROM processes p
LEFT JOIN processes pp ON p.parent = pp.pid
LEFT JOIN hash ON pp.path = hash.path
WHERE p.on_disk != 1
AND age > 60 -- false positives from recently spawned processes
AND p.pid > 0
AND p.parent != 2 -- kthreadd
AND p.state != 'Z'
AND NOT (
    p.gid=20 AND
    (
        -- NOTE: p.path is typically empty when on_disk != 1, so don't depend on it.
        cmd LIKE "/Library/Apple/System/%"
        OR cmd LIKE "/Applications/Google Chrome.app/%"
        OR cmd LIKE "/Applications/Logi Options.app/Contents/%"
        OR cmd LIKE "/Applications/Safari.app/%"
        OR cmd LIKE "/Applications/Visual Studio Code.app/Contents%"
        OR cmd LIKE "/Library/Apple/System/%"
        OR cmd LIKE "/Library/Application Support/Logitech.localized/%"
        OR cmd LIKE "/Library/Developer/CommandLineTools/%"
        OR cmd LIKE "/opt/homebrew/Cellar/%"
        OR cmd LIKE "/private/var/folders/%/Visual Studio Code.app/Contents/%"
        OR cmd LIKE "/Users/%/homebrew/opt/mysql/bin/%"

        -- Sometimes cmd is empty also :(
        OR parent_cmd LIKE "/Applications/Google Chrome.app/%"
    )
)
