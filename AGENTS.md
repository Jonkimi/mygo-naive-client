# AGENTS.md

For general MyGo UI engineering, lifetime management, animations, and i18n guidelines, refer to the `mygo-maintenance` skill (`/mygo-maintenance`).

## Tests

Only write a test for behaviour that can actually break. If the code under test could change without the test noticing, or the test would fail on a harmless rewording, don't write it.

**Write tests for:**

- What input does: clicks, keys, form submission, importing and exporting links, starting and stopping services, switching modes, and the state or effect they lead to.
- Logic that doesn't need a view: generating NaiveProxy, Sing-Box, and Xray configs and routing rules, parsing and exporting `socks://address:port#alias` (V2rayN) and `naive+https://` links, circuit-breaker and health telemetry state machines, WARP and Tailnet logic, matching platform release assets from GitHub Releases, verifying SHA256 digests, and managing process lifecycle. Prefer testing form validation, field coupling, and config previews at the state/logic layer instead of driving them through drawer clicks and scroll offsets.
- A regression you just fixed. Say in the test's comment what went wrong.
- Frame budgets, so idle views don't start asking for frames they don't need.

**Don't write tests that:**

- Check that a list of labels shows on screen. That repeats the view code and breaks whenever the wording changes.
- Check default settings or the order of rows in a form.
- Test MyGo itself, for example that `AnimateTo` or a spring moves from 0 to 1.
- Depend on the wall clock or `time.Sleep` for UI timing. `ui.NewTester` starts its clock at the current time and stands still until `tt.Advance(...)` moves it, so anything with a phase taken from the clock passes or fails depending on when the test runs. Also, `FramePending` ignores frames waiting on `After` or `Painter.After`.
- Rely on brittle pixel offsets (`tt.ClickAt(rect.X+10, ...)`) or manual `scroll.Y` tweaks to hit form controls.

**How:**

- Build views with `newTestApp` (in `internal/app/app_test.go`), which uses `ui.NewTester` with default desktop preferences so transitions and `FramePending()` idle-budget checks match normal user sessions. After opening or closing drawers/popovers with `Transition` (or triggering timed animations), advance the tester's virtual clock with `tt.Advance(...)` (e.g. `300 * time.Millisecond` for 200 ms drawer transitions) before clicking controls inside them or asserting `FramePending()`. Use `tt.SetPreferences(ui.Preferences{ReduceMotion: true})` only when explicitly testing reduced-motion behaviour.
- Locate text controls via `a.catalog().<Method>()` (keeping tests locale-safe) and unlabeled controls (icon buttons, switches) via a stable `.Label(...)` or `tt.AccessByRole`, then drive them with `Click`, `RightClick`, `Press`/`Move`/`Release`, `Type`, or `Key`, and check the app's state afterwards.
- Isolate external side effects (system proxy, TUN, subprocesses, network) through instance-level injection in `newTestApp` rather than mutating global package variables when avoidable; if a package-level seam must be swapped, restore the real one with `defer`. Use `tt.Clipboard()` / `tt.SetClipboard()` (or `a.clipboardMem` where the headless fallback applies) for clipboard tests.
- Live tests that hit real network endpoints must skip unless `LIVE` is set (and skip under `testing.Short()`).
- Start each test with a one-sentence comment saying the behaviour it checks, in the style of the code.
- Before committing, run `go tool mygo vet .` and `go test ./...`, and run any new UI test with `-count=5`. Fix or delete a flaky test; don't retry it.
