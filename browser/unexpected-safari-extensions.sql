
-- Based on the Kolide data collection query - YMMV.
WITH app_extensions_flat AS (
    SELECT *
    FROM plist
    WHERE path LIKE '/Applications/%.app/Contents/PlugIns/%.appex/Contents/Info.plist'
),
app_extension_pivot AS (
    SELECT SPLIT(path, '/', 1) AS extension_parent_app,
        '/' | | SPLIT(path, '/', 0) | | '/' | | SPLIT(path, '/', 1) AS parent_app_path,
        MAX(
            CASE
                WHEN key = 'CFBundleIdentifier' THEN value
            END
        ) AS bundle_identifier,
        MAX(
            CASE
                WHEN key = 'CFBundleDisplayName' THEN value
            END
        ) AS display_name,
        MAX(
            CASE
                WHEN key = 'NSHumanReadableDescription' THEN value
            END
        ) AS description,
        MAX(
            CASE
                WHEN key = 'CFBundleShortVersionString' THEN value
            END
        ) AS bundle_short_version,
        MAX(
            CASE
                WHEN key = 'CFBundleVersion' THEN value
            END
        ) AS bundle_version,
        MAX(
            CASE
                WHEN key = 'NSHumanReadableCopyright' THEN value
            END
        ) AS copyright
    FROM app_extensions_flat
    GROUP BY path
),
human_accounts AS (
    SELECT username,
        uid,
        directory
    FROM users
    WHERE SUBSTR(uuid, 0, 8) ! = 'FFFFEEE'
),
safari_raw AS (
    SELECT username,
        uid,
        MAX(
            CASE
                WHEN key = 'Enabled' THEN value
            END
        ) AS enabled,
        MAX(
            CASE
                WHEN key = 'AddedDate' THEN CAST(value AS datetime)
            END
        ) AS added_date,
        MAX(
            CASE
                WHEN key LIKE '%Level' THEN value
            END
        ) AS level,
        MAX(
            CASE
                WHEN key LIKE '%Has Injected Content' THEN value
            END
        ) AS has_injected_content,
        MAX(
            CASE
                WHEN path LIKE '%AppExtensions/Extensions.plist' THEN 'app'
                WHEN path LIKE '%WebExtensions/Extensions.plist' THEN 'web'
            END
        ) AS extension_type,
        REGEX_SPLIT(parent, ' \(', 0) AS bundle_identifier,
        REGEX_MATCH(parent, '\((.*?)\)', 1) AS extension_id
    FROM kolide_plist
        JOIN human_accounts ha ON directory = '/Users/' | | SPLIT(path, '/', 1)
    WHERE path LIKE '/Users/%/Library/Containers/com.apple.Safari/Data/Library/Safari/%Extensions/Extensions.plist'
    GROUP BY SPLIT(parent, '/', 0),
        path
),
safari_group_concat AS (
    SELECT SPLIT(parent, ' ', 0) AS bundle_identifier,
        GROUP_CONCAT(value, ', ') AS web_ext_permissions_csv
    FROM kolide_plist
    WHERE path LIKE '/Users/%/Library/Containers/com.apple.Safari/Data/Library/Safari/%Extensions/Extensions.plist'
        AND parent LIKE '%/Permissions%'
    GROUP BY bundle_identifier
),
-- Remove nulls
safari_extensions_plist AS (
    SELECT *
    FROM safari_raw
),
merge_data AS (
    SELECT *
    FROM safari_extensions_plist
        LEFT JOIN app_extension_pivot USING(bundle_identifier)
        LEFT JOIN safari_group_concat USING(bundle_identifier)
),
parent_app_bundle_id AS (
    SELECT md.*,
        value AS parent_app_bundle_identifier
    FROM merge_data md
        LEFT JOIN plist ON path = (parent_app_path | | '/Contents/Info.plist')
        AND key = 'CFBundleIdentifier'
),
parent_app_description AS (
    SELECT parent_app_bundle_id.*,
        value AS parent_app_bundle_description
    FROM parent_app_bundle_id
        LEFT JOIN plist ON path = (parent_app_path | | '/Contents/Info.plist')
        AND key = 'NSHumanReadableDescription'
)
SELECT (username | | '/' | | bundle_identifier) AS 'unique_id',
    display_name AS 'display_name',
    bundle_identifier AS 'bundle_identifier',
    extension_id AS 'team_identifier',
    extension_type AS 'extension_type',
    web_ext_permissions_csv AS 'permissions',
    uid AS 'uid',
    username AS 'username',
    added_date AS 'installed_at_epoch',
    COALESCE(description, parent_app_bundle_description) AS 'description',
    copyright AS 'copyright',
    level AS 'level',
    enabled AS 'enabled',
    bundle_version AS 'bundle_version',
    bundle_short_version AS 'version',
    parent_app_path AS 'parent_app_path',
    parent_app_bundle_identifier AS 'parent_app_bundle_identifier',
    has_injected_content AS 'has_injected_content'
FROM parent_app_description
WHERE ()