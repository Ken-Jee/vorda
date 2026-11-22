# State storage and recovery

Vorda keeps unresolved findings, delivery history, and the latest scan checkpoint for each scope. It never silently prunes old scopes or deletes evidence when storage fills up.

The `storage` MCP tool inspects the selected state folder without changing it. It reports total bytes, entry count, bytes per top-level path, limits, and admission status. It never follows symlinks, errors past 100,000 entries, and looks only inside the configured state folder.

Default limits are 512 MiB total, 64 MiB per atomic file, and 256 MiB for mailbox SQLite growth. Larger existing databases are not shrunk. You can put `storage-policy.json` in the state folder with positive integers for `max_bytes` and `max_file_bytes`. Use lower limits to test storage pressure without filling a disk.

When admission fails, Vorda refuses each native state write or atomic file write with an error and keeps existing evidence intact. Read-only checks and saved findings still work over budget. You can archive a stopped state folder to separate storage, verify the copy, and switch to a new state folder; Vorda never moves or deletes it automatically. Changing a limit is always an explicit local config choice. These checks are not a filesystem quota and do not confine subprocess output. Other processes can still touch the folder, and SQLite can still reuse already allocated pages.

Scan checkpoints commit in SQLite with findings and Assets. Derived `inbox.jsonl`, `INBOX.md`, and `last-scan.json` files rebuild when the store opens if their generation marker lags. If admission blocks recovery, a warning names SQLite as the authority, and recovery retries after operator action. A kill before commit leaves the prior transaction intact; a kill after commit keeps the new result for rebuild. This is crash recovery, not a guarantee against power loss or failed hardware.

Attention reads check up to 512 candidate messages per call and return up to the requested 1–100 items. A scope-filtered page can be empty with a non-null cursor; keep going with that cursor. The cursor tracks live message history, not a frozen snapshot. The serialized MCP result stays under 2 MB including escaped text; any single item too large to fit is refused so you can inspect it locally. Reads never acknowledge deliveries or close findings.
