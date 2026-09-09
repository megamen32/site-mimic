# site-mimic Python client

`site_mimic_client/gohttp.py` — the canonical requests-flavoured drop-in that
routes site HTTP through the local fetchd daemon (`cmd/fetchd`). Stdlib-only,
packaged via `pyproject.toml` and installed as a git dependency — no file
copies, no mirrors.

## Install (consumer repos)

```sh
pip install git+https://github.com/megamen32/site-mimic.git@python-v0.1.0#subdirectory=python
```

Versions live HERE: bump `version` in `python/pyproject.toml`, tag the commit
as `python-vX.Y.Z`, then re-pin the tag in consumer repos (their `pyproject.toml` + `requirements.txt`). Raw commit SHA pins are for
hotfix verification only, not for requirements.

## Config (env)

- `GOHTTPD_URL` — daemon base, default `http://127.0.0.1:30777`
- `GOHTTPD_TOKEN` — optional bearer when fetchd runs with FETCHD_TOKEN
- `GOHTTPD_BIN` / `SITE_MIMIC_DIR` — where the client finds/builds the fetchd
  binary for self-supervision (healthz → spawn → retry)
- `GOHTTP_PROFILE` — mimic profile.json selecting the transport identity

The client self-supervises the daemon: healthz before each call, spawn +
single retry on a dead daemon. Callers that need hard guarantees add their
own fallback (retry/impit/etc. in the caller).
