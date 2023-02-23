-- Return the list of installed Firefox addons
--
-- tags: postmortem
-- platform: posix
SELECT firefox_addons.*
FROM users
    JOIN firefox_addons ON users.uid = firefox_addons.uid;