-- Indicative of stored GCP service account keys just sitting around unencrypted
--
-- * False positives:
--   * Keys exported for non-production purposes
--
-- tags: persistent state filesystem disabled
-- platform: darwin
SELECT
  file.path,
  file.size,
  file.btime,
  file.ctime,
  file.mtime,
  magic.data,
  hash.sha256,
  u.username,
  ea.value AS url
FROM
  mdfind
  JOIN file ON mdfind.path = file.path
  LEFT JOIN users u ON file.uid = u.uid
  LEFT JOIN hash ON mdfind.path = hash.path
  LEFT JOIN extended_attributes ea ON mdfind.path = ea.path
  AND ea.key = 'where_from'
  LEFT JOIN magic ON mdfind.path = magic.path
  LEFT JOIN signature ON mdfind.path = signature.path
WHERE
  mdfind.query = "kMDItemFSName == '*.json'"
  AND (
    file.filename LIKE "%-%-%.json"
    OR file.filename LIKE '%service%.json'
    OR file.filename LIKE '%acct%.json'
    OR file.filename LIKE '%key%.json'
    OR file.filename LIKE '%account%.json'
    OR file.filename LIKE '%-sa.json'
    OR file.filename LIKE 'sa%.json'
    OR file.filename LIKE '%s%r%v%acc%t%json'
    OR file.filename LIKE '%prod.json'
    OR file.filename LIKE 'prod%.json'
  )
  AND file.size BETWEEN 2311 AND 2385 -- Don't alert on tokens that begin with the username-, as they may be personal
  AND NOT INSTR(file.filename, CONCAT (u.username, "-")) == 1 -- Don't alert on tokens that begin with the users full name and a dash
  AND NOT (
    LENGTH(u.username) > 4
    AND INSTR(file.filename, SUBSTR(u.username, 3, 8)) > 0
  )
  AND NOT INSTR(
    file.filename,
    REPLACE(LOWER(TRIM(u.description)), " ", "-")
  ) == 1
  -- Common locations of test or demo keys
  AND NOT file.filename = 'keys.json'
  AND NOT file.directory = "/Users/Shared/LGHUB"
  AND NOT file.directory LIKE '%/pkg/%'
  AND NOT file.directory LIKE '%/go/src/%'
  AND NOT file.directory LIKE '%/pkg/mod/%'
  AND NOT file.directory LIKE '%/aws-sdk/apis'
  AND NOT file.directory LIKE '%/mock-infras/%'
  AND NOT file.directory LIKE '%/testdata%'
  AND NOT file.directory LIKE '%/conformance/%'
  AND NOT file.directory LIKE '%/third_party/%'
  AND NOT file.directory LIKE '%/generated/%'
  AND NOT file.directory LIKE '%/output/%'
  AND NOT file.directory LIKE '%/tests%'
  AND NOT file.directory LIKE '%/validation%'
  AND NOT file.directory LIKE '%/data/%'
  AND NOT file.directory LIKE '%/json%'
  AND NOT file.directory LIKE '%/specs%'
  AND NOT file.directory LIKE '%/schemas'
  AND NOT file.directory LIKE '/Users/%/Library/Application Support/%'
  AND NOT file.directory LIKE '%demo'
  AND NOT file.filename LIKE 'ntia-conformance-%'
  AND NOT file.filename LIKE '%-test.json'
  AND NOT file.filename LIKE '%package%'
  AND NOT file.filename LIKE '%expected%'
  AND NOT file.filename LIKE '%.pom.%'
  AND NOT file.filename LIKE '%latest%'
  AND NOT file.filename LIKE '%2022%'
  AND NOT file.filename LIKE '%2023%'
  AND NOT file.filename LIKE 'host-project-%'
  AND NOT file.filename LIKE '%spdx%'
  AND NOT file.filename LIKE '%-v1%'
  AND NOT file.filename LIKE 'libopenblas-%'
  -- Well known demo keys
  AND NOT hash.sha256 IN (
    '11ffc5141b4b0071c0796914deef68d012c4f4c289931c5587fe89d7d6dca0a1',
    '2d330d059f4af4d314a85418fb031ee628f41dcf3e31fbce46858e52e73180c4',
    '4b4be8c1bc7e3bc7ea1f02932a024466db5faf3eaad885cf31ac7383484b1b1c',
    '6e55f3eccad59a615189c82cbcbd1133ce94509f7c5d42e3e7fbd00e65f0731f',
    'e99b4e6dfbbefa19c9ec9c82bb0c3445a443702f960c2a05f882bb5577a59ef8',
    '421899fb9bfa0252ce7921969339918a5bbacbc7b9cd500e03a88f9c4e33bae4',
    '81bce2313cd00ffc42303fbf7c08e4d068fccc9c0076867903ef94616d795e12',
    '8d740893c1f9163ddfd8c193d9a95caf15da3740b42f2739c4b107ad12661809',
    '998ddcb7d1a7c2931c8546576873e47b399f23cef719227052f245c8240c6528',
    'af1a2f8e9d581bb1504e3d8801d15d962fdf12ee7ebcf2bb9c475c8b92da6472',
    'b68896dc8e8c23ade371cf8b5c9d25853d81b4cfa5baa2bc0200d9242a903d80',
    'bc4c0ad21d79fea9050e75e80f13dd54bfdc867236342ede901d15d815f31988',
    'cea85342377ef1bce115629c3d9d3ec405964a43545805c9f7ace98940aa0be2',
    'a0f925d91d2ae1d38c13305572b2bf027e09f39e8bea575d55e8fcd5f3bf8b32',
    'ef2c928c69403e023a332002d8c5c430e1022850b12f834563f6aec111d99f14'
  )
GROUP BY
  file.path
