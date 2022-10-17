-- Detect the execution of a Docker containing mounting the root filesystem
--
-- references:
--   * https://attack.mitre.org/techniques/T1611/
--   * https://github.com/liamg/traitor/blob/main/pkg/exploits/dockersock/exploit.go
--
-- This attack is very quick, so the likelihood of finding a culprit is entirely
-- dependent on the polling time. The number of "tags" you see associated to an image
-- may reflect the number of times the attack has been attempted.
--
-- platform: linux
-- tags: transient often
SELECT
  *
FROM
  docker_image_history
WHERE
  created > (strftime('%s', 'now') -86400)
  -- This signature is used by Traitor: https://github.com/liamg/traitor/
  AND created_by LIKE '%/bin/sh%/lol%';
