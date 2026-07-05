# Tests

The test suite uses the Python standard library plus `pytest` as the preferred
runner.

```bash
pytest
python -m unittest discover -s tests
```

The tests cover:

- DNS question parsing and response construction.
- Upstream response parsing and forward-cache behavior.
- Media IP tracker persistence and pruning.
- Per-source rate limiting and private-network checks.
- UDP per-client voice/media routing selection.
