-- Find database exports. Will need tuning based on your table names.

SELECT f.path,
    f.size,
    datetime(f.btime, "unixepoch") AS file_created,
    magic.data
FROM file f
    JOIN mdfind ON mdfind.path = f.path
    LEFT JOIN magic ON f.path = magic.path
WHERE (
        (
            mdfind.query = "kMDItemFSName == '*enforce*' && kMDItemTextContent == 'CREATE TABLE'"
        )
        OR (
            mdfind.query = "kMDItemFSName == '*iam*' && kMDItemTextContent == 'CREATE TABLE'"
        )
        OR (
            mdfind.query = "kMDItemFSName == '*tenant*' && kMDItemTextContent == 'CREATE TABLE'"
        )
    )
    AND f.path NOT LIKE "%.json"
    AND f.path NOT LIKE "%.log"
    AND f.size > 32768