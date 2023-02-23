-- Returns information about running processes(non-hidden only)
--
-- tags: postmortem
-- platform: linux
SELECT GROUP_CONCAT(processes.pid) AS processes,
GROUP_CONCAT(processes.name) AS names,
file.*, hash.sha256,
magic.data
FROM processes
LEFT JOIN file ON processes.path = file.path
LEFT JOIN hash ON processes.path = hash.path
LEFT JOIN magic ON processes.path = magic.path
GROUP BY processes.path