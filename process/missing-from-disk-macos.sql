SELECT p.pid, p.path, p.parent, p.state, p.cwd, p.gid, p.uid, p.euid, p.cmdline, p.on_disk, p.state, pp.on_disk AS parent_on_disk, pp.path AS parent_path, pp.cmdline AS parent_cmdline, hash.sha256 AS parent_hash
FROM processes p
JOIN processes pp ON p.parent = pp.pid
LEFT JOIN hash ON pp.path = hash.path
WHERE p.on_disk != 1
AND p.pid > 0
AND p.parent != 2 -- kthreadd
AND NOT (
    -- User Zombie processes
    p.gid=20 AND p.state='Z' AND p.path=''
)
AND NOT (
    p.gid=20 AND
    (
        pp.path LIKE "/Applications/Docker.app/Contents/%"
        OR pp.path LIKE "/Users/%/Library/Application Support/Figma/FigmaAgent.app/Contents/MacOS/figma_agent"
        OR p.path LIKE "/opt/homebrew/Cellar/%"
        OR p.path LIKE "/private/var/folders/%/Visual Studio Code.app/Contents/%"
        OR p.path LIKE "%.sandboxTrash/Slack.app%"
        OR p.cmdline LIKE "%/Applications/Visual Studio Code.app/Contents%"
    )
)
