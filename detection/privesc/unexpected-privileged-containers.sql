-- Detect the execution of priveleged Docker containers which can be used to escape to the host.
--
-- references:
--   * https://attack.mitre.org/techniques/T1611/
--
-- false-positives:
--   * Nested Kubernetes Environments
--   * Containerized builds
--
-- This query works on macOS as well, but is only an in-the-wild security problem on Linux,
-- where the kernel namespaces can be shared. These kind of attacks tend to be
--
-- platform: linux
-- tags: transient state container escalation
SELECT
  command,
  image_id,
  path,
  security_options,
  started_at,
  image
FROM
  docker_containers
WHERE
  privileged = 1
  AND image NOT LIKE 'kindest/node:%'
  AND image NOT LIKE 'ghcr.io/k3d-io/k3d-%'
  AND image NOT LIKE 'docker.io/rancher/k3s:%'
  -- this one makes me sad. It's due to limitations running bubblewrap in a container
  AND image NOT IN ('cgr.dev/chainguard/melange', 'wolfi:test');
