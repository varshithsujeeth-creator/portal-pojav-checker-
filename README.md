# Portal Checker (Android / PojavLauncher port)

Ported from `PortalHackChecker.exe`. Same cheat-client name list, same
mod-metadata detection idea, same "weak heuristic vs strong hit" report
structure — adapted for scanning PojavLauncher's `.minecraft` folder on
Android instead of a Windows filesystem.

## Why Shizuku, and what it means for whoever installs this

Normal Android apps cannot read another app's files. Shizuku is a
separate, free, open-source app that grants *this* app permission to run
shell-level commands (the same access level `adb shell` has), which is
enough to read PojavLauncher's `.minecraft` folder even though it lives
outside this app's sandbox.

**The person running this app has to, once:**
1. Install Shizuku from the Play Store or GitHub (`RikkaApps/Shizuku`).
2. Start it — either by pairing over ADB from a PC once, or on Android 11+
   using Shizuku's own wireless-debugging starter (no PC needed), or
   automatically on rooted devices.
3. Open Portal Checker and tap "Grant Shizuku Permission" (one popup, one tap).

There's no version of this that skips that step entirely and "just works"
silently — that's the Android permission model, not a limitation of this
app's code.

## Building the actual .apk

### Option A: GitHub Actions (no local Android Studio needed)
This project includes `.github/workflows/build.yml`. Push it to a GitHub
repo and it builds automatically — see the full walkthrough in the chat
where this was generated, or the short version:
1. Create a new GitHub repo, push this folder's contents to it.
2. GitHub Actions runs automatically on push to `main` (or trigger it
   manually from the Actions tab → "Build Debug APK" → "Run workflow").
3. Once it finishes (green check), open that run → **Artifacts** section
   → download `app-debug` → unzip it to get `app-debug.apk`.

### Option B: Android Studio locally
```bash
# On a machine with Android Studio installed:
1. Open this folder as an Android Studio project (File > Open)
2. Let Gradle sync (it will download the Shizuku API + Compose libraries)
3. Build > Build Bundle(s)/APK(s) > Build APK(s)
4. Find it in app/build/outputs/apk/debug/app-debug.apk
```

## What's ported vs. what's different from the PC version

| PC (.exe) | Android (this app) |
|---|---|
| Walks Windows folders directly | Walks PojavLauncher's `.minecraft` via Shizuku shell access |
| Reads any file freely | Reads via `find`/`cat`/`sha256sum` shell calls (same result, different plumbing) |
| Tkinter UI | Jetpack Compose UI, same color palette |
| `portal_network_ss_baseline.json` report | Same JSON shape, shown in-app as a findings list |
| OpenAI review call | Not wired up yet — add your own API key in `Scanner.kt` if you want it |

## Known gaps / things to test on a real device

- The known PojavLauncher paths in `Scanner.KNOWN_POJAV_PATHS` cover the
  common install locations, but PojavLauncher has changed its storage path
  across versions — if a scan finds nothing, check the actual path on the
  device and add it to that list.
- Some OEM Android builds restrict shell-level access to `Android/data`
  even with Shizuku running; this varies by manufacturer and Android
  version. If scanning fails there, the app reports it clearly rather than
  pretending to have scanned.
- Jar/zip inspection currently pulls each file into the app's cache dir
  temporarily to read it — fine for typical mod sizes, but very large
  files could be slow.
