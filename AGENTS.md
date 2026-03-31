# AGENTS

## Zweck

Diese Datei ist die kleine Repo-Oberflaeche fuer ein separates Projekt-Repo.
Host-Betrieb, Firewall, SSH, globale Backups und Browser-Tooling bleiben im
Host-Repo.

## Erst lesen

1. `README.md`
2. `ops/deploy-contract.v1.yaml`

## Wahrheitsquellen

- `README.md`
  - aktueller Projektzustand, lokaler QA-Pfad und kurze Proof-Zusammenfassung
- `ops/deploy-contract.v1.yaml`
  - gewuenschter Normalzustand plus `notes` fuer Steady-State und Proof-Hinweise
- `tools/proof/`
  - projektlokale browserlose Proof-Helfer fuer Auth-/Session- und
    Restore-Readbacks

## Harte Regeln

- keine Secrets, Tokens, Keys oder Browserdaten in Git
- `README.md` und `ops/deploy-contract.v1.yaml` im selben Arbeitsblock
  nachziehen, wenn sich der reale Proof- oder Steady-State aendert
- Host-Runbooks nicht in dieses Repo kopieren
- Proof-only Endpunkte duerfen vor einem Public-Proof nicht offen bleiben
- PostgreSQL bleibt hier die durable source of truth
- Restore-Gegenbeweise bleiben projekt-eigen; der generische Hostpfad liefert
  nur Dump-, Restore- und Artefakt-Helfer
- bei intentionalen verhaltensaendernden Defektfixes:
  - Failure erst belegen
  - den kleinsten faithful projekt-lokalen Regression-Check waehlen
  - danach den repo-lokalen Closeout-Pfad schliessen

## Pflicht-Gates vor "fertig" oder "clean"

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File tools/repo/check-project-closeout.ps1
git status --short --ignored
```

## README-Mindestform

- `## Charakter`
- `## Aktueller Zustand`
- `## Lokale Entwicklung`
- `## Laufzeitverhalten`
- entweder `## Proof-Status` oder `## Reale Evidence`
