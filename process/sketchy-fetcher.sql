SELECT p.pid,
    p.path,
    p.name,
    p.cmdline,
    p.cwd,
    p.euid,
    p.parent,
    pp.path AS parent_path,
    pp.name AS parent_name,
    pp.cmdline AS parent_cmdline,
    pp.euid AS parent_euid
FROM processes p
    JOIN processes pp ON p.parent = pp.pid
WHERE
(
    p.cmdline LIKE "%.onion%" OR
    p.cmdline LIKE "%tor2web%" OR
    p.cmdline LIKE "%aliyun%" OR
    p.cmdline LIKE "%pastebin%" OR
    p.cmdline LIKE "%curl %/.%" OR
    p.cmdline LIKE "%curl %.0%" OR
    p.cmdline LIKE "%curl %.1%" OR
    p.cmdline LIKE "%curl %.2%" OR
    p.cmdline LIKE "%curl %.3%" OR
    p.cmdline LIKE "%curl %.4%" OR
    p.cmdline LIKE "%curl %.5%" OR
    p.cmdline LIKE "%curl %.6%" OR
    p.cmdline LIKE "%curl %.7%" OR
    p.cmdline LIKE "%curl %.8%" OR
    p.cmdline LIKE "%curl %.9%" OR
    p.cmdline LIKE "%curl %:0%" OR
    p.cmdline LIKE "%curl %:1%" OR
    p.cmdline LIKE "%curl %:2%" OR
    p.cmdline LIKE "%curl %:3%" OR
    p.cmdline LIKE "%curl %:4%" OR
    p.cmdline LIKE "%curl %:5%" OR
    p.cmdline LIKE "%curl %:6%" OR
    p.cmdline LIKE "%curl %:7%" OR
    p.cmdline LIKE "%curl %:8%" OR
    p.cmdline LIKE "%curl %:9%" OR
    p.cmdline LIKE "%curl %--user-agent%" OR
    p.cmdline LIKE "%curl -fsSL%" OR
    p.cmdline LIKE "%curl -k%" OR
    p.cmdline LIKE "%curl%--insecure%" OR
    p.cmdline LIKE "%wget %/.%" OR
    p.cmdline LIKE "%wget %.0%" OR
    p.cmdline LIKE "%wget %.1%" OR
    p.cmdline LIKE "%wget %.2%" OR
    p.cmdline LIKE "%wget %.3%" OR
    p.cmdline LIKE "%wget %.4%" OR
    p.cmdline LIKE "%wget %.5%" OR
    p.cmdline LIKE "%wget %.6%" OR
    p.cmdline LIKE "%wget %.7%" OR
    p.cmdline LIKE "%wget %.8%" OR
    p.cmdline LIKE "%wget %.9%" OR
    p.cmdline LIKE "%wget %--user-agent%" OR
    p.cmdline LIKE "%wget %--no-check-certificate%"
)
AND p.cmdline NOT LIKE "%If-None-Match%"
AND parent_name NOT IN ('makepkg')
AND parent_cmdline NOT LIKE "%brew.rb upgrade"
AND parent_cmdline NOT LIKE "%brew.sh update"
