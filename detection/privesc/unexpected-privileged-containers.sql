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
  image,
  COALESCE(REGEX_MATCH (image, '(.*?):', 1), image) AS image_name
FROM
  docker_containers
WHERE
  privileged = 1
  AND image_name NOT IN (
    'cgr.dev/chainguard/melange',
    'cgr.dev/chainguard/apko',
    'cgr.dev/chainguard/python',
    'cgr.dev/chainguard/sdk',
    'cgr.dev/chainguard/wolfi-base',
    'distroless.dev/melange',
    'docker.io/rancher/k3s',
    'cgr.dev/chainguard-private/python',
    'gcr.io/k8s-minikube/kicbase',
    'ghcr.io/wolfi-dev/sdk',
    'kindest/node',
    -- blame k3d/k3s for this
    'docker.io/library/registry',
    'moby/buildkit',
    'wolfi'
  )
  AND image NOT LIKE 'ghcr.io/k3d-io/k3d-%'
  AND image NOT LIKE 'melange-%'
  AND command NOT LIKE '/usr/bin/melange build %'
