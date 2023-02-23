-- Return the list of watched file events (must be configured)
--
-- tags: postmortem
-- platform: posix
SELECT
  *
FROM
  file_events;