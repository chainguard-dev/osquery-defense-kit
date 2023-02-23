-- Retrieves chrome extension cotent scripts that execute on a broad set of URLs.
-- tags: postmortem
-- platform: posix
SELECT chrome_extension_content_scripts.*
FROM users
    JOIN chrome_extension_content_scripts ON users.uid = chrome_extension_content_scripts.uid
