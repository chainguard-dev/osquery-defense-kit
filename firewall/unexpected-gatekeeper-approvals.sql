-- -- https://posts.specterops.io/hunting-for-bad-apples-part-2-6f2d01b1f7d3
SELECT * FROM gatekeeper_approved_apps
WHERE
path NOT LIKE "/Users/%/code/bin/protoc"
