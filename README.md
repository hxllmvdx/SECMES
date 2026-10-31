# SECMES

## Stack

1. Rust core (all in `crates`, `crypto-core`, `server`, `proto`): `crypto-core` uses only STD library, `server` uses `tonic` gRPC server, `proto` uses `tonic` to build files.
2. Frontend (`desktop`): `desktop` uses `Tauri` + `React` to make desktop UI
3. DBs: `PostgreSQL` for `server` stores users, chats, etc. `SQLite` for storing encrypted chat history. `MinIO` to store files and media.
4. Redpanda: for consistency, to deliver messages.
