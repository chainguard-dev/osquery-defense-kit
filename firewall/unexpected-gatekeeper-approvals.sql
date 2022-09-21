-- -- https://posts.specterops.io/hunting-for-bad-apples-part-2-6f2d01b1f7d3
SELECT gap.ctime, gap.mtime, gap.path, file.mtime, file.uid, file.ctime, file.gid, hash.sha256, signature.identifier, signature.authority
FROM gatekeeper_approved_apps AS gap
LEFT JOIN file ON gap.path = file.path
LEFT JOIN hash ON gap.path = hash.path
LEFT JOIN signature ON gap.path = signature.path
WHERE gap.path NOT LIKE "/Users/%/code/bin/protoc"
AND gap.path NOT LIKE "/Users/%/Downloads/rekor-cli"
AND gap.path NOT LIKE "/Users/%/bin/rekor-cli"
GROUP BY gap.requirement