-- Detect the execution of privileged Docker containers which can be used to escape to the host.
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
    'cgr.dev/chainguard-private/python',
    'cgr.dev/chainguard/apko',
    'cgr.dev/chainguard/k3s',
    'cgr.dev/chainguard/melange',
    'cgr.dev/chainguard/python',
    'cgr.dev/chainguard/sdk',
    'cgr.dev/chainguard/wolfi-base',
    'distroless.dev/melange',
    'docker.io/library/registry',
    'docker.io/rancher/k3s',
    'gcr.io/k8s-minikube/kicbase',
    'ghcr.io/wolfi-dev/sdk',
    'ghcr.io/wolfi-dev/sdk@sha256',
    'kindest/node',
    'ligfx/k3d-registry-dockerd',
    'moby/buildkit',
    'wolfi'
  )
  AND image NOT LIKE 'ghcr.io/k3d-io/k3d-%'
  AND image NOT LIKE 'ghcr.io/wolfi-dev/%'
  AND image NOT LIKE 'melange-%'
  AND image NOT LIKE 'k3d-k3d.localhost:%'
  AND command NOT LIKE '/usr/bin/melange build %'
