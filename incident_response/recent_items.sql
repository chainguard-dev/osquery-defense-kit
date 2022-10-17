-- Retrieves the list of recent items opened in OSX by parsing the plist per user.
--
-- interval: 86400
-- platform: darwin
-- value: Identify recently accessed items. Useful for compromised hosts.
-- version: 1.4.5
select
  username,
  key,
  value
from
  plist p,
  (
    select
      *
    from
      users
    where
      directory like '/Users/%'
  ) u
where
  p.path = u.directory || '/Library/Preferences/com.apple.recentitems.plist';
