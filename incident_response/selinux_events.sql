-- Return the list of SELinux events
--
-- tags: postmortem events
-- platform: linux
SELECT
  *
FROM
  selinux_events;
