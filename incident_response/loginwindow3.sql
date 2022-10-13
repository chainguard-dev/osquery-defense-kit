-- Retrieves all the values for the loginwindow process in the target OSX system.
--
-- interval: 86400
-- platform: darwin
-- value: Identify malware that uses this persistence mechanism to launch at system boot
-- version: 1.4.5

select username, key, subkey, value from plist p, (select * from users where directory like '/Users/%') u where p.path = u.directory || '/Library/Preferences/com.apple.loginwindow.plist';
