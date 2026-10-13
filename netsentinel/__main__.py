"""Command line: python -m netsentinel [serve | create-user | reset-password]"""
import argparse
import getpass
import sys
import threading
import webbrowser

from . import __version__, env as envmod, paths
from .auth import AuthError
from .core import Core


def _serve(args):
    e = envmod.load()
    if args.host:
        e.host = args.host
        e.host_check_disabled = e.host_check_disabled or not e.is_loopback
    if args.port:
        e.port = args.port
    core = Core()
    from .server import create_app
    app = create_app(core, e)
    if e.autocapture:
        try:
            core.capture.start(core.settings.get("capture_iface"))
        except Exception as ex:
            print(f"[netsentinel] auto-capture could not start: {ex}")
    print(f"NetSentinel {__version__}  |  http://{e.host}:{e.port}  |  data: {core.data_dir}")
    if core.auth.count() == 0:
        print(f"First run: open the site and create the administrator with setup code  {e.setup_code}")
        print("          (or run: python -m netsentinel create-user --role admin)")
    if not e.is_loopback and not e.secure_cookies:
        print("WARNING: listening on a network address without HTTPS. Put it behind a TLS reverse proxy "
              "and set NETSENTINEL_SECURE_COOKIES=1 (see docs/DEPLOYMENT.md).")
    if getattr(args, "open", False):
        url = f"http://{'127.0.0.1' if e.host in ('0.0.0.0', '') else e.host}:{e.port}"
        threading.Timer(1.5, lambda: webbrowser.open(url)).start()
    try:
        from waitress import serve
        serve(app, host=e.host, port=e.port, threads=8, ident="NetSentinel")
    except ImportError:
        print("(waitress not installed: using the development server. pip install waitress for production.)")
        app.run(host=e.host, port=e.port, threaded=True, debug=False)


def _create_user(args):
    core = Core()
    pw = args.password or getpass.getpass("Password: ")
    try:
        core.auth.create(args.username or input("Username: "), pw, args.role)
    except AuthError as ex:
        sys.exit(f"Error: {ex}")
    core.auth.audit(None, "user_created_cli", args.username or "")
    print("User created.")


def _reset_password(args):
    core = Core()
    row = core.db.query("SELECT id FROM users WHERE username = ?", (args.username,))
    if not row:
        sys.exit("No such user.")
    try:
        core.auth.update(row[0]["id"], password=args.password or getpass.getpass("New password: "), disabled=False)
    except AuthError as ex:
        sys.exit(f"Error: {ex}")
    core.auth.audit(None, "password_reset_cli", args.username)
    print("Password changed and the account re-enabled. Existing sessions were signed out.")


def main(argv=None):
    p = argparse.ArgumentParser(prog="netsentinel", description="Self-hosted network scanner and traffic monitor.")
    sub = p.add_subparsers(dest="cmd")
    s = sub.add_parser("serve", help="start the web app (default)")
    s.add_argument("--host"); s.add_argument("--port", type=int)
    s.add_argument("--open", action="store_true", help="open the web app in your browser")
    c = sub.add_parser("create-user", help="add a user from the command line")
    c.add_argument("username", nargs="?"); c.add_argument("--role", default="admin", choices=["viewer", "analyst", "admin"]); c.add_argument("--password")
    r = sub.add_parser("reset-password", help="reset a forgotten password")
    r.add_argument("username"); r.add_argument("--password")
    args = p.parse_args(argv)
    {"create-user": _create_user, "reset-password": _reset_password}.get(args.cmd, _serve)(args if args.cmd else argparse.Namespace(host=None, port=None, open=paths.frozen()))


if __name__ == "__main__":
    main()
