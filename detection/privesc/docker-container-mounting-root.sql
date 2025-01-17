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
-- tags: transient container escalation
SELECT
  command,
  image_id,
  path,
  source,
  destination,
  security_options,
  started_at,
  image
FROM
  docker_container_mounts AS dcm
  LEFT JOIN docker_containers dc ON dcm.id = dc.id
WHERE
  dcm.source = "/"
  AND image NOT IN (
    "ghcr.io/ublue-os/ubuntu-toolbox",
    "ghcr.io/ublue-os/bluefin-cli"
  )
  AND image NOT LIKE '%wolfi-sdk-toolbox:latest'
