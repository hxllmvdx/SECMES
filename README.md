# SECMES

## Stack

1. Rust core (`crypto-core`, `server`): `crypto-core` uses only STD library, `server` uses `tonic` gRPC server.
2. Frontend (`desktop`): `desktop` uses `Tauri` + `React` to make desktop UI
3. DBs: `PostgreSQL` for `server` stores users, chats, etc. `SQLite` for storing encrypted chat history. `MinIO` to store files and media.
4. Redpanda: for consistency, to deliver messages.
