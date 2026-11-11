# AccountsKeeper

A lightweight native Windows password manager written in C++ with no third-party library dependencies.

## Features

- **Native Win32 UI** — account list with columns for Product/URL, Username, Password, Additional notes, and Created date.
- **Account editor** — fields for Product/URL, Username, Password (with show/hide toggle), and a multiline Additional notes field.
- **Toolbar actions** — Refresh, New, Save, Delete, Copy Username, Copy Password.
- **Client-side DPAPI encryption** — all account fields are encrypted with Windows DPAPI (`dpapi:v1:` prefix) before leaving the machine; Turso only ever stores ciphertext.
- **Turso cloud sync** — CRUD operations against a Turso (libSQL) database over its HTTP API, authenticated with the `Turso_Token` environment variable.
- **Offline fallback** — when Turso is unreachable the app falls back to a local JSON backup (`%APPDATA%\AccountsKeeper\accounts_backup.json`).
- **Auto-sync on refresh** — accounts that exist only in the local backup are automatically uploaded to Turso on the next successful refresh.
- **Global hotkey** — `Ctrl + Alt + K` toggles the window from anywhere.
- **System tray** — closing the window hides it to the tray; the tray menu can reopen or fully exit the app.
- **Single instance** — launching a second instance brings the existing window to the foreground.
- **Optional startup** — register or remove the app from the Windows `Run` registry key via a checkbox in the settings panel.
- **HTTP proxy support** — optional proxy with username/password authentication; proxy password is stored encrypted via DPAPI.
- **Settings persistence** — proxy and startup preferences are saved to `%APPDATA%\AccountsKeeper\settings.ini`.

## Turso setup

The app creates the table automatically (`CREATE TABLE IF NOT EXISTS`, see `sql/turso_create_accounts.sql`):

```text
accounts(id text PK, product_name_url text, username text, password text, additional text, created_at text)
```

Set the auth token (and optionally override the database URL; the default is built in):

```powershell
[Environment]::SetEnvironmentVariable("Turso_Token", "your-turso-token", "User")
# optional: [Environment]::SetEnvironmentVariable("Turso_URL", "libsql://your-db.turso.io", "User")
```

To migrate existing Supabase data (and any local-backup-only rows) into Turso, with `SUPABASE_URL` / `SUPABASE_KEY` still set:

```powershell
.\scripts\migrate_to_turso.ps1
```

The script is idempotent and copies ciphertext as-is.
## Build

Requires Visual Studio 2022 with the **Desktop development with C++** workload.

### CMake (recommended)

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
.\build\Release\AccountsKeeper.exe
```

### Direct MSVC (single command)

```powershell
.\build_msvc.bat
.\build-direct\AccountsKeeper.exe
```

`build_msvc.bat` auto-detects the Visual Studio installation via `vswhere`, compiles `src/main.cpp` as C++17, and links against `advapi32`, `comctl32`, `crypt32`, `gdi32`, `ole32`, `shell32`, `shlwapi`, `user32`, and `winhttp` — all Windows SDK libraries, no external dependencies.

## Encryption

Account fields are encrypted with **AES-256-CBC** using a key derived from your master password via **PBKDF2-SHA256** (200 000 iterations).  A fixed application-wide salt ensures the same password produces the same key on every machine, so any Windows PC running AccountsKeeper can decrypt data stored in Turso — just use the same master password everywhere.

The master password is never stored anywhere.  A small verification blob (`settings.ini [master] verify`) is written locally on each machine so the app can confirm the correct password was entered before loading data.

**First run on a new machine:**  
The app will prompt you to enter a master password.  If you have data on another machine already, enter **the same password** you used there — the confirmation field is shown so you type it twice.  If you mistype and create a different password, Turso data will fail to decrypt (you'll see "(decrypt failed)" entries).  Delete the verify blob by removing `[master]` from `%APPDATA%\AccountsKeeper\settings.ini` and relaunch.

**Legacy data (DPAPI-encrypted blobs):**  
If you previously ran an older version, data already in the database carries a `dpapi:v1:` prefix and can still be read on the original machine.  To make it readable everywhere, open each account, then click **Save** — it will be re-encrypted with AES-256 and overwritten in Turso.

Proxy passwords remain DPAPI-encrypted because they are a per-machine setting.
