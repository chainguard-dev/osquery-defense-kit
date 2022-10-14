-- Detect the execution of a Docker containing mounting the root filesystem
--
-- references:
--   * https://attack.mitre.org/techniques/T1611/
--   * https://github.com/liamg/traitor/blob/main/pkg/exploits/dockersock/exploit.go
--
-- This attack is very quick, so the likelihood of finding a culprit is entirely
-- dependent on the polling time.
--
-- platform: linux
-- tags: transient often container escalation
SELECT
  command, image_id, path, security_options, started_at, image
FROM
  docker_containers
WHERE
  privileged = 1
  AND image NOT LIKE 'kindest/node:%';
