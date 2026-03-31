import argparse
import json
from pathlib import Path

import httpx


def load_cookies(cookie_file: Path | None) -> dict[str, str]:
    if cookie_file is None or not cookie_file.exists():
        return {}
    return json.loads(cookie_file.read_text(encoding='utf-8'))


def save_cookies(cookie_file: Path | None, cookies: dict[str, str]) -> None:
    if cookie_file is None:
        return
    cookie_file.write_text(json.dumps(cookies, indent=2), encoding='utf-8')


def build_client(base_url: str, cookie_file: Path | None, https_forwarded: bool) -> httpx.Client:
    headers = {}
    if https_forwarded:
        headers['x-forwarded-proto'] = 'https'
    client = httpx.Client(base_url=base_url, headers=headers, follow_redirects=False)
    for key, value in load_cookies(cookie_file).items():
        client.cookies.set(key, value)
    return client


def response_payload(response: httpx.Response) -> object:
    content_type = response.headers.get('content-type', '')
    if 'application/json' in content_type:
        return response.json()
    return response.text


def dump_response(response: httpx.Response) -> dict[str, object]:
    return {
        'status_code': response.status_code,
        'headers': dict(response.headers),
        'body': response_payload(response),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=['login', 'me', 'items', 'admin-users', 'logout'])
    parser.add_argument('--base-url', required=True)
    parser.add_argument('--cookie-file')
    parser.add_argument('--email')
    parser.add_argument('--password')
    parser.add_argument('--https-forwarded', action='store_true')
    args = parser.parse_args()

    cookie_file = Path(args.cookie_file) if args.cookie_file else None
    with build_client(args.base_url, cookie_file, args.https_forwarded) as client:
        if args.command == 'login':
            if not args.email or not args.password:
                raise SystemExit('--email and --password are required for login')
            response = client.post(
                '/auth/login',
                json={'email': args.email, 'password': args.password},
            )
        elif args.command == 'me':
            response = client.get('/auth/me')
        elif args.command == 'items':
            response = client.get('/items')
        elif args.command == 'admin-users':
            response = client.get('/admin/users')
        else:
            response = client.post('/auth/logout')

        save_cookies(cookie_file, dict(client.cookies))
        print(json.dumps(dump_response(response), indent=2))
        return 0 if response.status_code < 400 else 1


if __name__ == '__main__':
    raise SystemExit(main())

