-- Return the list of socket events
--
-- tags: postmortem
-- platform: posix
-- interval: 600
SELECT
  *
FROM
  socket_events
WHERE time > (strftime('%s', 'now') -600)
