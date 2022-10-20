-- Return the list of configured DNS servers on this system
--
-- tags: postmortem
-- platform: posix
SELECT
  *
FROM
  dns_resolvers;
