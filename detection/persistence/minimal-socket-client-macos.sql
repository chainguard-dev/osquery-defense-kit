-- Slow query to find root programs with an open socket and few shared libraries
--
-- false positives:
--   * some minimalist daemons
--
-- references:
--   * https://www.deepinstinct.com/blog/bpfdoor-malware-evolves-stealthy-sniffing-backdoor-ups-its-game
--
-- tags: persistent process state seldom
-- platform: macos
SELECT p.uid,
    p.euid,
    pos.protocol,
    pos.pid,
    pos.remote_address,
    pos.local_address,
    pos.local_port,
    pos.remote_port,
    p.name,
    p.parent,
    p.cgroup_path,
    p.path,
    pos.state,
    GROUP_CONCAT(pmm.path) AS libs,
    COUNT(DISTINCT pmm.path) AS lib_count,
    CONCAT(MIN(p.euid, 500), ',', p.name, ',', s.authority, ',', s.identifier) AS exception_key
FROM processes p
    JOIN process_open_sockets pos ON p.pid = pos.pid AND family != 1
    LEFT JOIN signature s ON p.path = s.path
    JOIN process_memory_map pmm ON pos.pid = pmm.pid 
WHERE p.pid IN (
        SELECT pid
        FROM processes
    )
    AND pmm.path LIKE "%.dylib"
AND exception_key NOT IN (
    '500,Slack,Apple Mac OS Application Signing,com.tinyspeck.slackmacgap',
    '500,Slack Helper (Renderer),Apple Mac OS Application Signing,com.tinyspeck.slackmacgap.helper',
    '500,Snagit 2020,Apple Mac OS Application Signing,com.TechSmith.Snagit2020',
    '500,SnagitHelper2020,Apple Mac OS Application Signing,com.techsmith.snagit.capturehelper2020',
    '500,Telegram,Apple Mac OS Application Signing,ru.keepcoder.Telegram',
    '500,Todoist,Apple Mac OS Application Signing,com.todoist.mac.Todoist'
)
GROUP BY pos.pid
HAVING lib_count IN (1, 2)