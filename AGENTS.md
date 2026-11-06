# AGENTS.md

For general MyGo UI engineering, lifetime management, animations, and i18n guidelines, refer to the `mygo-maintenance` skill (`/mygo-maintenance`).

## Tests

Only write a test for behaviour that can actually break. If the code under test could change without the test noticing, or the test would fail on a harmless rewording, don't write it.

**Write tests for:**

- What input does: clicks, keys, form submission, importing and exporting links, starting and stopping services, and the state or effect they lead to.
- Logic that doesn't need a view: generating `config.json` according to `USAGE.txt`, parsing and exporting `socks://address:port#alias` (V2rayN) and `naive+https://` links, matching platform release assets from GitHub Releases, verifying SHA256 digests, and managing process lifecycle.
- A regression you just fixed. Say in the test's comment what went wrong.
- Frame budgets, so idle views don't start asking for frames they don't need.

**Don't write tests that:**

- Check that a list of labels shows on screen. That repeats the view code and breaks whenever the wording changes.
- Check default settings or the order of rows in a form.
- Test MyGo itself, for example that `AnimateTo` or a spring moves from 0 to 1.
