# AccountsKeeper

A lightweight native Windows password manager written in C++ with no third-party library dependencies.

## Features

- **Native Win32 UI** — account list with columns for Product/URL, Username, Password, Additional notes, and Created date.
- **Account editor** — fields for Product/URL, Username, Password (with show/hide toggle), and a multiline Additional notes field.
- **Toolbar actions** — Refresh, New, Save, Delete, Copy Username, Copy Password.
- **Client-side DPAPI encryption** — all account fields are encrypted with Windows DPAPI (`dpapi:v1:` prefix) before leaving the machine; Supabase only ever stores ciphertext.
- **Supabase cloud sync** — CRUD operations against a Supabase REST API using `SUPABASE_URL` and `SUPABASE_KEY` environment variables.
- **Offline fallback** — when Supabase is unreachable the app falls back to a local JSON backup (`%APPDATA%\AccountsKeeper\accounts_backup.json`).
- **Auto-sync on refresh** — accounts that exist only in the local backup are automatically uploaded to Supabase on the next successful refresh.
- **Global hotkey** — `Ctrl + Alt + K` toggles the window from anywhere.
- **System tray** — closing the window hides it to the tray; the tray menu can reopen or fully exit the app.
- **Single instance** — launching a second instance brings the existing window to the foreground.
- **Optional startup** — register or remove the app from the Windows `Run` registry key via a checkbox in the settings panel.
- **HTTP proxy support** — optional proxy with username/password authentication; proxy password is stored encrypted via DPAPI.
- **Settings persistence** — proxy and startup preferences are saved to `%APPDATA%\AccountsKeeper\settings.ini`.

## Supabase setup

Create the table with:

```sql
-- sql/create_accounts.sql
```

The app expects this schema:

```text
accounts(id uuid PK, product_name_url text, username text, password text, additional text, created_at timestamptz)
```

If the table already exists and you need to (re-)apply row-level security policies, use:

```sql
-- sql/fix_rls_accounts.sql
```

Set the environment variables before running:

```powershell
$env:SUPABASE_URL="https://your-project.supabase.co"
$env:SUPABASE_KEY="your-anon-key"
```

For persistent user environment variables:

```powershell
[Environment]::SetEnvironmentVariable("SUPABASE_URL", "https://your-project.supabase.co", "User")
[Environment]::SetEnvironmentVariable("SUPABASE_KEY", "your-anon-key", "User")
```

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

Account fields are encrypted with **AES-256-CBC** using a key derived from your master password via **PBKDF2-SHA256** (200 000 iterations).  A fixed application-wide salt ensures the same password produces the same key on every machine, so any Windows PC running AccountsKeeper can decrypt data stored in Supabase — just use the same master password everywhere.

The master password is never stored anywhere.  A small verification blob (`settings.ini [master] verify`) is written locally on each machine so the app can confirm the correct password was entered before loading data.

**First run on a new machine:**  
The app will prompt you to enter a master password.  If you have data on another machine already, enter **the same password** you used there — the confirmation field is shown so you type it twice.  If you mistype and create a different password, Supabase data will fail to decrypt (you'll see "(decrypt failed)" entries).  Delete the verify blob by removing `[master]` from `%APPDATA%\AccountsKeeper\settings.ini` and relaunch.

**Legacy data (DPAPI-encrypted blobs):**  
If you previously ran an older version, data already in Supabase carries a `dpapi:v1:` prefix and can still be read on the original machine.  To make it readable everywhere, open each account, then click **Save** — it will be re-encrypted with AES-256 and overwritten in Supabase.

Proxy passwords remain DPAPI-encrypted because they are a per-machine setting.
