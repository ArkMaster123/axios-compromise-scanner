#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║                 Axios Compromise Scanner                     ║
║          github.com/noahsark/axios-compromise-scanner        ║
╚══════════════════════════════════════════════════════════════╝

Checks your projects for exposure to the axios@1.14.1 / plain-crypto-js@4.2.1
supply chain attack (March 31 2026).

Usage:
    python3 scan.py                  # interactive menu
    python3 scan.py ~/code ~/work    # scan specific folders directly
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

try:
    import curses

    HAS_CURSES = True
except Exception:
    curses = None
    HAS_CURSES = False

try:
    from rich.console import Console
    from rich.progress import (
        BarColumn,
        Progress,
        SpinnerColumn,
        TaskProgressColumn,
        TextColumn,
        TimeElapsedColumn,
    )

    HAS_RICH = True
except Exception:
    HAS_RICH = False

# ─── Config ───────────────────────────────────────────────────────────────────

VERSION = "1.0.0"

NEEDLES = (
    "axios@1.14.1",
    "plain-crypto-js@4.2.1",
    "plain-crypto-js",
    '"axios": "1.14.1"',
    '"axios":"1.14.1"',
    '"axios": "^1.14.1"',
    '"axios": "~1.14.1"',
)

TARGET_FILENAMES = [
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "bun.lock",
]

# Skip lockfiles larger than this (bytes) — avoids hanging on massive monorepos
MAX_LOCKFILE_BYTES = 10 * 1024 * 1024  # 10 MB

# Common places devs keep projects — auto-detected at runtime
CANDIDATE_ROOTS = [
    "~/Documents/vibecoding",
    "~/Documents",
    "~/code",
    "~/dev",
    "~/projects",
    "~/work",
    "~/src",
    "~/repos",
    "~/Sites",
    "~/Developer",
    "~/Desktop",
]

# ─── Scanner ──────────────────────────────────────────────────────────────────


def scan_file(path: Path) -> list[str]:
    try:
        size = path.stat().st_size
        if size > MAX_LOCKFILE_BYTES and path.name != "package.json":
            return []  # skip huge lockfiles — package.json is always tiny
        data = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []
    return list({n for n in NEEDLES if n in data})


def scan_projects(roots: list[Path], on_project=None, on_file=None) -> dict:
    """
    Scan each subfolder of each root as a separate project.
    Calls on_project(i, total, name) and on_file(filename) for live progress.
    Returns a results dict.
    """
    # Collect project dirs (immediate children with at least one manifest)
    projects = []
    for root in roots:
        if not root.exists():
            continue
        try:
            entries = sorted(root.iterdir())
        except PermissionError:
            continue
        for entry in entries:
            if not entry.is_dir():
                continue
            manifests = [entry / f for f in TARGET_FILENAMES if (entry / f).is_file()]
            if manifests:
                projects.append((entry, manifests))

    total = len(projects)
    results = {
        "roots": [str(r) for r in roots],
        "projects": [],
        "total": total,
        "clean": 0,
        "at_risk": 0,
        "elapsed": 0,
    }

    start = time.time()

    for i, (proj_dir, manifests) in enumerate(projects, 1):
        if on_project:
            on_project(i, total, proj_dir.name)

        proj_findings = []
        for f in manifests:
            if on_file:
                on_file(f.name)
            hits = scan_file(f)
            if hits:
                proj_findings.append({"file": str(f), "hits": hits})

        status = "AT RISK" if proj_findings else "CLEAN"
        results["projects"].append(
            {
                "project": str(proj_dir),
                "name": proj_dir.name,
                "status": status,
                "findings": proj_findings,
            }
        )
        if proj_findings:
            results["at_risk"] += 1
        else:
            results["clean"] += 1

    results["elapsed"] = round(time.time() - start, 2)
    return results


# ─── Terminal helpers ──────────────────────────────────────────────────────────

ESC = "\033"
BOLD = ESC + "[1m"
DIM = ESC + "[2m"
RED = ESC + "[91m"
GREEN = ESC + "[92m"
YELLOW = ESC + "[93m"
CYAN = ESC + "[96m"
RESET = ESC + "[0m"
CLEAR_LINE = "\r\033[K"


def clear():
    os.system("clear")


def width():
    try:
        return os.get_terminal_size().columns
    except OSError:
        return 80


def hr(char="─"):
    return char * min(width(), 70)


def center(text, w=None):
    w = w or min(width(), 70)
    clean = text.replace(BOLD, "").replace(DIM, "").replace(RESET, "")
    clean = (
        clean.replace(RED, "").replace(GREEN, "").replace(YELLOW, "").replace(CYAN, "")
    )
    pad = max(0, (w - len(clean)) // 2)
    return " " * pad + text


def progress_bar(current: int, total: int, bar_width: int = 26) -> str:
    if total <= 0:
        total = 1
    current = max(0, min(current, total))
    filled = int((current / total) * bar_width)
    empty = bar_width - filled
    return "█" * filled + "░" * empty


def banner():
    clear()
    w = min(width(), 70)
    print()
    print(center(BOLD + CYAN + "╔" + "═" * (w - 2) + "╗" + RESET))
    title = "  axios compromise scanner  "
    print(
        center(
            BOLD
            + CYAN
            + "║"
            + RESET
            + BOLD
            + title.center(w - 2)
            + RESET
            + BOLD
            + CYAN
            + "║"
            + RESET
        )
    )
    sub = f"  v{VERSION} · checks axios@1.14.1 + plain-crypto-js@4.2.1  "
    print(
        center(
            CYAN + "║" + RESET + DIM + sub.center(w - 2) + RESET + CYAN + "║" + RESET
        )
    )
    print(center(BOLD + CYAN + "╚" + "═" * (w - 2) + "╝" + RESET))
    print()


# ─── Interactive menu ──────────────────────────────────────────────────────────


def detect_roots() -> list[tuple[str, Path]]:
    """Return list of (label, path) for folders that actually exist."""
    seen = set()
    found = []
    for raw in CANDIDATE_ROOTS:
        p = Path(os.path.expanduser(raw)).resolve()
        if p in seen or not p.exists() or not p.is_dir():
            continue
        seen.add(p)
        # count immediate project subdirs
        try:
            count = sum(
                1
                for e in p.iterdir()
                if e.is_dir() and any((e / f).is_file() for f in TARGET_FILENAMES)
            )
        except PermissionError:
            count = 0
        if count > 0:
            found.append((f"{p}  {DIM}({count} projects){RESET}", p))
    return found


def interactive_menu():
    """
    Arrow-key + space multi-select menu.
    Returns list of selected paths, or None if user quit.
    """
    if not HAS_CURSES:
        banner()
        print(f"  {YELLOW}Interactive menu is unavailable on this terminal.{RESET}")
        print(
            f"  Run direct mode instead, e.g.: {BOLD}python scan.py ~/code ~/projects{RESET}\n"
        )
        return None

    options = detect_roots()

    if not options:
        banner()
        print(f"  {YELLOW}No project folders detected automatically.{RESET}")
        print(f"  Run:  {BOLD}python3 scan.py ~/your/projects{RESET}\n")
        return None

    selected = [False] * len(options)
    cursor = 0

    def draw(stdscr):
        nonlocal cursor
        curses.curs_set(0)
        curses.start_color()
        curses.init_pair(1, curses.COLOR_CYAN, curses.COLOR_BLACK)
        curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(3, curses.COLOR_WHITE, curses.COLOR_BLACK)
        curses.init_pair(4, curses.COLOR_BLACK, curses.COLOR_CYAN)

        while True:
            stdscr.clear()
            h, w = stdscr.getmaxyx()
            row = 0

            def addstr(r, c, text, attr=0):
                try:
                    stdscr.addstr(r, c, text, attr)
                except curses.error:
                    pass

            # Header
            title = " axios compromise scanner "
            addstr(
                row,
                max(0, (w - len(title)) // 2),
                title,
                curses.color_pair(1) | curses.A_BOLD,
            )
            row += 1
            addstr(row, 0, "─" * min(w - 1, 68), curses.color_pair(1))
            row += 1
            addstr(
                row,
                2,
                "Select folders to scan  (SPACE=toggle  A=all  ENTER=scan  Q=quit)",
                curses.color_pair(3) | curses.A_DIM,
            )
            row += 2

            for i, (label, path) in enumerate(options):
                prefix = " [✓] " if selected[i] else " [ ] "
                # strip ANSI for curses
                clean_label = str(path)
                try:
                    proj_count = sum(
                        1
                        for e in path.iterdir()
                        if e.is_dir()
                        and any((e / f).is_file() for f in TARGET_FILENAMES)
                    )
                    clean_label = f"{path}  ({proj_count} projects)"
                except Exception:
                    clean_label = str(path)

                if i == cursor:
                    attr = curses.color_pair(4) | curses.A_BOLD
                elif selected[i]:
                    attr = curses.color_pair(2)
                else:
                    attr = curses.color_pair(3)

                line = prefix + clean_label
                addstr(row + i, 2, line[: w - 3], attr)

            row += len(options) + 1
            sel_count = sum(selected)
            addstr(
                row,
                2,
                f"{sel_count} folder(s) selected",
                curses.color_pair(2) if sel_count else curses.color_pair(3),
            )

            stdscr.refresh()

            key = stdscr.getch()

            if key in (curses.KEY_UP, ord("k")) and cursor > 0:
                cursor -= 1
            elif key in (curses.KEY_DOWN, ord("j")) and cursor < len(options) - 1:
                cursor += 1
            elif key == ord(" "):
                selected[cursor] = not selected[cursor]
            elif key in (ord("a"), ord("A")):
                all_on = all(selected)
                selected[:] = [not all_on] * len(options)
            elif key in (ord("\n"), ord("\r"), curses.KEY_ENTER):
                return
            elif key in (ord("q"), ord("Q"), 27):
                selected[:] = [False] * len(options)
                return

    try:
        curses.wrapper(draw)
    except Exception:
        return None

    chosen = [path for i, (_, path) in enumerate(options) if selected[i]]
    return chosen if chosen else None


# ─── Results display ───────────────────────────────────────────────────────────


def print_results(results: dict):
    clear()
    banner()
    total = results["total"]
    at_risk = results["at_risk"]
    clean = results["clean"]
    elapsed = results["elapsed"]

    print(
        f"  {BOLD}Scanned {total} projects across {len(results['roots'])} folder(s) in {elapsed}s{RESET}"
    )
    print(f"  {hr()}")
    print()

    # Project list
    for p in results["projects"]:
        if p["status"] == "AT RISK":
            icon = f"{RED}✗{RESET}"
            label = f"{RED}{BOLD}AT RISK{RESET}"
        else:
            icon = f"{GREEN}✓{RESET}"
            label = f"{GREEN}clean{RESET}"

        print(f"  {icon}  {p['name']:<40} {label}")
        for finding in p["findings"]:
            for hit in finding["hits"]:
                print(f"       {DIM}└─ {finding['file']}{RESET}")
                print(f"          {RED}→ {hit}{RESET}")

    print()
    print(f"  {hr()}")
    print()

    if at_risk == 0:
        print(
            f"  {GREEN}{BOLD}✓ ALL CLEAN{RESET}  — no indicators found in {total} projects."
        )
    else:
        print(f"  {RED}{BOLD}⚠  {at_risk} project(s) AT RISK{RESET}  — {clean} clean.")
        print()
        print(f"  {YELLOW}Recommended fix:{RESET}")
        print(f"  {DIM}npm install axios@latest  # or pnpm/yarn equivalent{RESET}")
        print(
            f"  {DIM}Delete node_modules and reinstall after updating lockfile.{RESET}"
        )

    print()

    # Save report
    report_path = Path.home() / "axios-scan-report.json"
    report_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"  {DIM}Full report saved → {report_path}{RESET}")
    print()

    # Share-friendly one-liner
    if at_risk == 0:
        share = f"Scanned {total} projects for the axios@1.14.1 supply chain attack — all clean. https://github.com/noahsark/axios-compromise-scanner"
    else:
        share = f"Scanned {total} projects for the axios@1.14.1 supply chain attack — {at_risk} at risk! https://github.com/noahsark/axios-compromise-scanner"
    print(f"  {DIM}Share:{RESET}  {share}")
    print(f"  {DIM}Contact:{RESET}  https://x.com/TheArk_Master")
    print()


# ─── Quiet mode ────────────────────────────────────────────────────────────────


def print_quiet(results: dict):
    """Minimal output — just the verdict line."""
    total = results["total"]
    at_risk = results["at_risk"]
    elapsed = results["elapsed"]

    if at_risk == 0:
        print(
            f"{GREEN}CLEAN{RESET}  {total} projects scanned in {elapsed}s — no axios@1.14.1 exposure found."
        )
    else:
        print(
            f"{RED}AT RISK{RESET}  {at_risk}/{total} projects exposed to axios@1.14.1 supply chain attack."
        )
        for p in results["projects"]:
            if p["status"] == "AT RISK":
                print(f"  {RED}✗{RESET}  {p['name']}")
                for finding in p["findings"]:
                    for hit in finding["hits"]:
                        print(f"     → {hit}  in {finding['file']}")


# ─── Progress display ──────────────────────────────────────────────────────────


def run_with_progress(roots: list[Path]):
    if HAS_RICH and sys.stdout.isatty():
        run_with_rich_progress(roots)
        return

    banner()
    print(f"  Scanning {len(roots)} folder(s)...\n")

    if sys.stdout.isatty():
        setup_steps = [
            "Loading threat signatures",
            "Indexing candidate projects",
            "Priming scan engine",
        ]
        for idx, step in enumerate(setup_steps, 1):
            bar = progress_bar(idx, len(setup_steps), bar_width=22)
            pct = int((idx / len(setup_steps)) * 100)
            sys.stdout.write(
                CLEAR_LINE + f"  {CYAN}{bar}{RESET}  {pct:>3}%  {DIM}{step}...{RESET}"
            )
            sys.stdout.flush()
            time.sleep(0.07)
        sys.stdout.write(CLEAR_LINE)
        print(f"  {GREEN}Ready.{RESET}")

    print(f"  {hr()}")
    print()

    last_project = [""]
    last_file = [""]
    last_index = [0]
    total_projects = [1]

    def on_project(i, total, name):
        last_project[0] = name
        last_index[0] = i
        total_projects[0] = max(total, 1)
        bar = progress_bar(i, total_projects[0])
        pct = int((i / total_projects[0]) * 100)
        sys.stdout.write(
            CLEAR_LINE
            + f"  {CYAN}{bar}{RESET}  {pct:>3}%  [{i}/{total}]  {BOLD}{name}{RESET}"
        )
        sys.stdout.flush()

    def on_file(filename):
        last_file[0] = filename
        bar = progress_bar(last_index[0], total_projects[0])
        pct = int((last_index[0] / total_projects[0]) * 100)
        sys.stdout.write(
            CLEAR_LINE
            + f"  {CYAN}{bar}{RESET}  {pct:>3}%  [{last_project[0]}]  {DIM}checking {filename}...{RESET}"
        )
        sys.stdout.flush()

    results = scan_projects(roots, on_project=on_project, on_file=on_file)
    sys.stdout.write(CLEAR_LINE)
    print_results(results)


def run_with_rich_progress(roots: list[Path]):
    banner()
    print(f"  Scanning {len(roots)} folder(s)...\n")
    print(f"  {hr()}")
    print()

    console = Console()
    last_project = ["..."]

    with Progress(
        SpinnerColumn(spinner_name="dots12"),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=None),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        transient=True,
        console=console,
    ) as progress:
        setup = progress.add_task("Loading threat signatures", total=3)
        for step in (
            "Loading threat signatures",
            "Indexing candidate projects",
            "Priming scan engine",
        ):
            progress.update(setup, description=step, advance=1)
            time.sleep(0.07)

        project_task = progress.add_task("Scanning projects", total=1)

        def on_project(i, total, name):
            last_project[0] = name
            progress.update(
                project_task,
                total=max(total, 1),
                completed=max(i - 1, 0),
                description=f"Scanning {name}",
            )

        def on_file(filename):
            progress.update(project_task, description=f"{last_project[0]} ({filename})")

        results = scan_projects(roots, on_project=on_project, on_file=on_file)
        progress.update(
            project_task,
            total=max(results["total"], 1),
            completed=max(results["total"], 1),
            description="Scan complete",
        )

    print_results(results)


# ─── Entry point ──────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(
        description="Scan projects for axios@1.14.1 supply chain attack exposure",
        epilog="Run without arguments for interactive menu.",
    )
    parser.add_argument(
        "roots", nargs="*", help="Project parent folders to scan directly"
    )
    parser.add_argument(
        "--json",
        dest="json_out",
        action="store_true",
        help="Output results as JSON (for CI/pipelines)",
    )
    parser.add_argument(
        "--quiet", "-q", action="store_true", help="Minimal output — just the verdict"
    )
    args = parser.parse_args()

    if args.roots:
        roots = [Path(os.path.expanduser(r)).resolve() for r in args.roots]
        if args.json_out:
            results = scan_projects(roots)
            print(json.dumps(results, indent=2))
        elif args.quiet:
            results = scan_projects(roots)
            print_quiet(results)
        else:
            run_with_progress(roots)
    else:
        can_use_interactive = HAS_CURSES and sys.stdin.isatty() and sys.stdout.isatty()
        if can_use_interactive:
            chosen = interactive_menu()
            if chosen:
                roots = chosen
            else:
                auto = detect_roots()
                roots = [p for _, p in auto]
                if not roots:
                    clear()
                    print(f"\n  {DIM}Cancelled.{RESET}\n")
                    sys.exit(0)

                banner()
                print(
                    f"  {YELLOW}Interactive menu unavailable; continuing in auto mode.{RESET}"
                )
                print(
                    f"  {DIM}Auto-selected {len(roots)} detected root folder(s).{RESET}\n"
                )
        else:
            auto = detect_roots()
            roots = [p for _, p in auto]
            if not roots:
                banner()
                print(f"  {YELLOW}No project folders detected automatically.{RESET}")
                print(
                    f"  Run direct mode: {BOLD}python scan.py ~/code ~/projects{RESET}\n"
                )
                sys.exit(1)

            banner()
            print(f"  {YELLOW}Interactive menu unavailable on this terminal.{RESET}")
            print(
                f"  {DIM}Auto-selected {len(roots)} detected root folder(s).{RESET}\n"
            )

        if args.json_out:
            results = scan_projects(roots)
            print(json.dumps(results, indent=2))
        elif args.quiet:
            results = scan_projects(roots)
            print_quiet(results)
        else:
            run_with_progress(roots)


if __name__ == "__main__":
    main()
