# Contributing

## Environment

- Python 3.10+
- Xcode, macOS, and a compiler are not required
- The Apple mobile device driver (Windows) is only needed for on-device installation tests

```bash
git clone <repo>
cd ipasign
python -m pip install -e ".[dev]"
```

With an editable install (`-e`), source changes take effect immediately — no reinstall needed.

## Common commands

```bash
python -m pytest -q              # all tests
python -m pytest tests/test_macho.py -q
python -m ipasign selfcheck      # dependency / path / device self-check
python -m ipasign                # interactive interface
```

## Code structure

```
ipasign/
├── app.py         entry point: no args → TUI, args → CLI
├── tui.py         interactive interface (rich)
├── cli.py         command line
├── paths.py       all path resolution (no hardcoded absolute paths)
├── device.py      installation (pymobiledevice3)
├── watch.py       automatic renewal task
├── core/          signing engine, independent of Apple services
└── apple/         sign-in, certificate requests, ADI
```

Two conventions:

1. **The core layer must not import the apple layer**; the signing engine should be usable standalone
2. **Every path goes through `paths.py`**; never write hardcoded paths like `C:\Users\...`

## Before committing

```bash
python -m pytest -q
```

CI runs the same tests on Python 3.10 / 3.11 / 3.12, and checks that the wheel bundles the native libraries.

## When changing signing logic

Every offset in `core/macho.py` corresponds to an iOS verification rule. If your change touches:

- CodeDirectory versions / flags
- special slots (Info.plist, Requirements, CodeResources, Entitlements, DER)
- the CMS hash agility attributes (`1.2.840.113635.100.9.1` / `.9.2`)

read the corresponding section of `docs/ARCHITECTURE.md` first, and add a regression case
to the tests (`tests/test_macho.py`, `tests/test_cms.py`).

## Documentation

- `README.md`: for users
- `docs/ARCHITECTURE.md`: for developers, including notes on pitfalls encountered
- `SECURITY.md`: data boundaries and vulnerability reporting
