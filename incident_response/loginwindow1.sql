-- Retrieves all the values for the loginwindow process in the target OSX system.
--
-- interval: 86400
-- platform: darwin
-- value: Identify malware that uses this persistence mechanism to launch at system boot
-- version: 1.4.5

select key, subkey, value from plist where path = '/Library/Preferences/com.apple.loginwindow.plist';
