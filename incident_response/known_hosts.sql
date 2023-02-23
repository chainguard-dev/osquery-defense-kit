-- Retrieves chrome extensions that execute on a broad set of URLs.
-- tags: postmortem
-- platform: posix
SELECT known_hosts.*
FROM users
    JOIN known_hosts ON users.uid = known_hosts.uid
