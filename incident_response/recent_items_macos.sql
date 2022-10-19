-- Retrieves the list of recent items opened in OSX by parsing the plist per user.
-- tags: postmortem
-- platform: darwin
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
