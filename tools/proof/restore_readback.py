import argparse
import json

from app.store import purge_workspace_sessions, read_workspace_state


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=['state', 'purge-sessions'])
    parser.add_argument('--database-url', required=True)
    args = parser.parse_args()

    if args.command == 'state':
        payload = read_workspace_state(args.database_url)
        print(json.dumps(payload, indent=2))
        return 0

    deleted = purge_workspace_sessions(args.database_url)
    print(json.dumps({'deleted_session_count': deleted}, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

