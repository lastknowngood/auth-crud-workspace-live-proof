# auth-crud-workspace-live-proof

Kleines separates Demo-Repo fuer einen generischen authentifizierten stateful
CRUD-Pfad auf `coolify-01`.

## Charakter

- `lifecycle.mode: live`
- stateful
- PostgreSQL als durable source of truth
- server-side DB-backed Sessions
- Rollen `admin` und `member`
- ein einzelner FastAPI-Prozess
- `operations.backup_class: stateful-logical-dump`
- Proof-Hostname: `auth.dental-school.education`
- Default-Endzustand des ersten Public-Proofs: Cleanup nach Evidence

## Aktueller Zustand

- das Repo ist lokal vorhanden und oeffentlich auf GitHub publiziert
- das Git-Repo ist initialisiert
- die Runtime-, Contract- und projektseitigen Proof-Helfer sind lokal vorhanden
- lokale Repo-Gates fuer Tests, Ruff, Pyright und Deptry sind gruen
- ein lokaler Docker-/Compose-PostgreSQL-Smoke ist auf diesem Rechner aktuell
  nicht belegbar, weil `docker` fehlt
- es gibt aktuell keinen Live-Dienst aus diesem Repo auf `coolify-01`
- `auth.dental-school.education` hat aktuell oeffentlich weder `A` noch `AAAA`
- es gibt aktuell keine Host-Ressourcen und keine lokalen Proof-Secrets fuer
  dieses Repo

## Lokale Entwicklung

Voraussetzungen:

- Python `3.12`
- `uv`
- optional Docker fuer PostgreSQL-Smoke-Checks

Schnellstart:

```powershell
uv sync
uv run pytest --cov=app
uv run ruff check .
uv run pyright
```

Optionaler lokaler Compose-Smoke:

```powershell
docker compose up -d postgres
$env:TEST_DATABASE_URL = 'postgresql://postgres:postgres@127.0.0.1:54330/auth_crud_workspace_live_proof'
uv run pytest --cov=app -m "not integration or integration"
```

Project-Closeout:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File tools/repo/check-project-closeout.ps1
git status --short --ignored
```

## Laufzeitverhalten

- `POST /auth/login` meldet User an und setzt eine server-side Session-Cookie
- `POST /auth/logout` entfernt die Session
- `GET /auth/me` read-backt den aktuellen User browserlos
- `GET /items` liefert fuer Member nur eigene Items, fuer Admin alle Items
- `POST /items`, `PATCH /items/{id}` und `DELETE /items/{id}` pruefen AuthZ
- `GET /admin/users` ist admin-only
- `POST /proof/reset` ist proof-only und seedet einen deterministischen
  privaten Basiszustand
- `GET /healthz` read-backt Status, Store, Build-Revision und Proof-Mode
- sichtbarer Root-Marker: `AUTH-CRUD-WORKSPACE-LIVE-PROOF OK`

## Proof-Status

- lokaler Code- und Testpfad ist gruen
- der aktuelle Deploy-Contract bleibt auf den ersten Proof-Ref
  `proof/auth-crud-workspace-live-proof-private-20260331-r1` ausgerichtet
- der private Host-Proof auf Commit
  `a36a70ec023d0b196591f0c5e1fe40ca21f7dc5a` war gruen:
  - Create- und Same-Ref-Redeploy
  - deterministischer Auth-/AuthZ-Pfad
  - Restart- und Redeploy-Persistenz
  - Dump, `host-restic-data-backup-run`, Restore-Cutover und Session-
    Invalidation auf dem Restore-Ziel
- der kurze Public-Proof auf demselben Ref war rot:
  - `HTTPS 200`, Root-Marker, `robots.txt`, `X-Robots-Tag` und
    `proof_mode=false` waren gruen
  - `POST /auth/login` lieferte oeffentlich fuer `member` und `admin`
    `401 invalid_credentials`
- same-day fail-closed Cleanup ist danach vollstaendig gruen gelaufen
- aktueller Steady State:
  - kein Live-Dienst
  - kein Public-DNS
  - keine Host-Ressourcen
  - keine lokalen Proof-Secrets
