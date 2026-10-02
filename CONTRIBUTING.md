# Contributing

Keep changes focused and include tests for altered behavior.

## Run locally

Use Python 3.12 or newer. No Python dependency installation is required.

```powershell
python server.py --demo
python -m unittest discover -s . -p "test_*.py" -v
node test_treemap.cjs
```

Real scanning is Windows-first. A platform-support change should address
volume discovery, allocation semantics, permissions, path classification and
cleanup guidance, not just make the server start on another OS.

## Data and safety

- Never commit real inventories, exports, logs or screenshots of personal data.
- Use `demo.py` or small synthetic test fixtures.
- Preserve read-only operation. No deletion, shell cleanup, elevation or cloud
  hydration should be added as a side effect of analysis.
- Do not infer that a file is unused from its last-modified timestamp.
- Treat cleanup sizes as upper bounds; include prerequisites and risks.
- Keep errors and unmeasured allocation visible.

Before submitting:

```powershell
git diff --cached
python scripts/check_release.py
```

The check examines the Git index. Stage your intended changes before running
it, and review the staged diff yourself.

## Screenshots

1. Run `python server.py --demo --port 8766`.
2. Open `http://127.0.0.1:8766/?theme=dark&chart=map`.
3. Confirm the **DEMO · SYNTHETIC DATA** banner is visible.
4. Capture the app without browser chrome, terminal output or other windows.
5. Save the repository screenshot as `docs/assets/demo.png`.

Do not capture the real-data server and try to redact it afterward. Check
that the image contains no personal paths or image metadata.

## UI text

Use short, descriptive labels. Describe what a view measures and what an
action does. Avoid slogans, promotional claims and unsupported safety claims.
