# AccountsKeeper — Feature & Requirement Plan

> **How to use this file:**
> Add new requirements under the `## Backlog` section using the template below.
> When you're ready to implement, tell me: _"Read PLAN.md and implement [item title]"_.
> I will move items between status sections as work progresses.

---

## Project Snapshot

| Item | Detail |
|---|---|
| Language | C++17, Win32 API (no third-party libs) |
| Build | CMake + MSVC (`build_msvc.bat`) |
| Storage | Supabase REST (cloud) + local JSON backup |
| Encryption | Windows DPAPI (`dpapi:v1:` prefix) per field |
| UI | Native Win32 dialog — list + editor panel + settings panel |
| Entry point | `src/main.cpp` (single-file app) |
| Resources | `src/AccountsKeeper.rc`, `src/resource.h` |

---

## Item Template

Copy this block into **Backlog** when adding a new requirement:

```
### [Short Title]
- **Type:** Feature | Bug | Improvement | Refactor
- **Priority:** High | Medium | Low
- **Description:**
  <!-- What should be added or changed, and why -->
- **Acceptance Criteria:**
  - [ ] ...
- **Notes / Constraints:**
  <!-- Any technical notes, UI hints, API details, etc. -->
```

---

## Status: In Progress

_Nothing in progress._

---

## Status: Backlog

_Nothing in backlog._

---

## Status: Completed

### [最上面按钮的可使用开关]
- **Type:** Feature
- **Priority:** High
- **Description:**
  添加一个Edit按钮，将它放在按钮行的最右边，默认它是没有被按下的，这个时候原本的所有按钮（New, Save等等）除了refresh都是不可点击的状态，只有当Edit按钮按下，这些按钮才能被使用。
- **Acceptance Criteria:**
  - [x] Edit button added at the far right of the toolbar row
  - [x] New, Save, Delete, Copy user, Copy pass are disabled by default
  - [x] Refresh is always enabled
  - [x] Pressing Edit enables all buttons (button visually appears depressed/pressed-in)
  - [x] Pressing Edit again disables all buttons (button returns to raised state)
- **Notes / Constraints:**
  Uses `BS_AUTOCHECKBOX | BS_PUSHLIKE` — button sinks in when active, raised when inactive.
