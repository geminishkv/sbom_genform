"""
CLI точка входа: secsbom / secsbom-pipeline

Команды:
  run     — полный пайплайн (генерация → сканирование → отчёты)
  format  — форматирование SBOM → xlsx / docx / odt
  verify  — проверка SHA-256 подписи
  info    — инспекция SBOM-файла
  status  — проверка доступности внешних инструментов
  diff    — сравнение двух SBOM
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box as rich_box

from . import __version__
from .banner import SECSBOMGEN, APPSECTA
from .config import PipelineConfig
from .pipeline import run as pipeline_run, format_sboms
from .sign import verify_sbom
from .utils import setup_logging

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = typer.Typer(
    name="secsbom",
    add_completion=False,
    rich_markup_mode="rich",
    pretty_exceptions_enable=False,
)
console = Console()


# ---------------------------------------------------------------------------
# Баннер
# ---------------------------------------------------------------------------

def _print_banner() -> None:
    """Вывести верхний баннер."""
    console.print(Align(f"[bold blue]{SECSBOMGEN}[/bold blue]", align="center"))
    console.print()
    console.print(Align(
        f"[bold white]SBOM Generator & Formatter[/bold white]  [dim]v{__version__}[/dim]",
        align="center",
    ))
    console.print(Align(
        "[dim]2026 Elijah S Shmakov (c) — AppSec Toolchain[/dim]",
        align="center",
    ))
    console.print()


def _print_footer() -> None:
    """Вывести нижний баннер APPSECTA."""
    console.print()
    console.print(Align(f"[bold blue]{APPSECTA}[/bold blue]", align="center"))
    console.print()
    console.print(Align("[italic dim]Sic Parvis Magna[/italic dim]", align="center"))


# ---------------------------------------------------------------------------
# Root callback — версия и общий help
# ---------------------------------------------------------------------------

def _version_callback(value: bool) -> None:
    if value:
        _print_banner()
        _print_footer()
        raise typer.Exit()


@app.callback(invoke_without_command=True)
def _main(
    ctx: typer.Context,
    version: Optional[bool] = typer.Option(
        None,
        "--version", "-V",
        help="Показать версию и выйти.",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    # help (no args / --help / -h) обрабатывается в main() до вызова Click
    pass


def _opt_row(
    t: Table,
    flag: str,
    short: str,
    typ: str,
    desc: str,
    envvar: str = "",
    default: str = "",
) -> None:
    """Добавить строку опции в формате скриншота."""
    meta_parts = []
    if envvar:
        meta_parts.append(f"[dim][env var: {envvar}][/dim]")
    if default:
        meta_parts.append(f"[dim][default: {default}][/dim]")
    meta = "  ".join(meta_parts)
    full_desc = f"[white]{desc}[/white]" + (f"\n{meta}" if meta else "")
    t.add_row(
        f"[bold blue]{flag}[/bold blue]",
        f"[blue]{short}[/blue]" if short else "",
        f"[cyan]{typ}[/cyan]" if typ else "",
        full_desc,
    )


def _opts_table() -> Table:
    t = Table(box=rich_box.SIMPLE, show_header=False, padding=(0, 1), show_edge=False)
    t.add_column("flag",  no_wrap=True, min_width=18)
    t.add_column("short", no_wrap=True, min_width=4)
    t.add_column("type",  no_wrap=True, min_width=5)
    t.add_column("desc")
    return t


def _print_help_table() -> None:
    """Единая справка по всем командам на русском."""
    console.print(
        "  [bold]secsbom[/bold] [dim][[/dim][italic]команда[/italic][dim]][/dim] "
        "[dim][[/dim][italic]опции[/italic][dim]][/dim]\n"
    )

    # ── Команды ──────────────────────────────────────────────────────────────
    cmd_t = Table(box=rich_box.SIMPLE, show_header=False, padding=(0, 2), show_edge=False)
    cmd_t.add_column("cmd",  no_wrap=True, min_width=10)
    cmd_t.add_column("desc", style="white")
    cmd_t.add_row("[bold green]run[/bold green]",    "Полный пайплайн: генерация → дедупликация → подпись → сканирование → отчёты")
    cmd_t.add_row("[bold green]format[/bold green]", "Форматирование готовых SBOM JSON → xlsx / docx / odt")
    cmd_t.add_row("[bold green]verify[/bold green]", "Проверка SHA-256 подписи SBOM  [dim]<файл>[/dim]")
    cmd_t.add_row("[bold green]info[/bold green]",   "Инспекция SBOM: компоненты, CVE по severity, подпись  [dim]<файл>[/dim]")
    cmd_t.add_row("[bold green]status[/bold green]", "Проверка окружения: Trivy / Docker / Node.js / Python")
    cmd_t.add_row("[bold green]diff[/bold green]",   "Сравнение двух SBOM: добавленные компоненты, новые CVE  [dim]<старый> <новый>[/dim]")
    cmd_t.add_row("[bold green]cert[/bold green]",   "Обогащение SBOM файла полями GOST:attack_surface, GOST:security_function  [dim]<файл>[/dim]")
    console.print(Panel(cmd_t, border_style="bright_black", padding=(0, 1)))

    # ── run options ───────────────────────────────────────────────────────────
    rt = _opts_table()
    _opt_row(rt, "--source",          "-s", "TEXT", "Источник: local | github | gitlab",         "SOURCE",         "local")
    _opt_row(rt, "--path",            "",   "PATH", "Путь к локальному проекту",                 "PROJECT_DIR",    "examples/project_inject")
    _opt_row(rt, "--url",             "",   "TEXT", "URL репозитория GitHub/GitLab",             "GIT_URL",        "")
    _opt_row(rt, "--token",           "",   "TEXT", "Токен доступа (ghp_... / glpat-...)",       "GIT_TOKEN",      "")
    _opt_row(rt, "--branch",          "",   "TEXT", "Ветка репозитория",                         "GIT_BRANCH",     "HEAD")
    _opt_row(rt, "--output-dir",      "-o", "PATH", "Директория артефактов SBOM",                "OUTPUT_DIR",     "secgensbom_out")
    _opt_row(rt, "--reports-dir",     "",   "PATH", "Директория отчётов",                        "REPORTS_DIR",    "secgensbom_reports")
    _opt_row(rt, "--image",           "",   "TEXT", "Docker-образ для сканирования Clair",       "IMAGE_NAME",     "")
    _opt_row(rt, "--clair-endpoint",  "",   "TEXT", "Endpoint Clair-сервера",                    "CLAIR_ENDPOINT", "http://clair:8080")
    _opt_row(rt, "--no-clair/--clair","",   "",     "Пропустить шаг Clair",                      "",               "no-clair")
    _opt_row(rt, "--bdu/--no-bdu",    "",   "",     "Обогащать уязвимости идентификаторами БДУ", "BDU",            "no-bdu")
    _opt_row(rt, "--verbose",         "-v", "",     "Подробный вывод (DEBUG-лог)",               "",               "false")

    examples = Table(box=None, show_header=False, padding=(0, 2), show_edge=False)
    examples.add_column()
    examples.add_row("[dim]Примеры:[/dim]")
    examples.add_row("[white]secsbom run[/white]  [dim]# локальный демо-проект[/dim]")
    examples.add_row("[white]secsbom run --path ./myproject[/white]")
    examples.add_row("[white]secsbom run --source github --url https://github.com/org/repo --token ghp_...[/white]")
    examples.add_row("[white]secsbom run --source gitlab --url https://gitlab.com/org/repo --token glpat-...[/white]")

    run_group = Table(box=None, show_header=False, padding=(0, 0), show_edge=False)
    run_group.add_column()
    run_group.add_row(rt)
    run_group.add_row(examples)
    console.print(Panel(run_group, title="[dim] run [/dim]", border_style="bright_black", padding=(0, 1)))

    # ── format options ────────────────────────────────────────────────────────
    ft = _opts_table()
    _opt_row(ft, "--sbom-dir",   "", "PATH", "Директория с готовыми SBOM JSON", "OUTPUT_DIR",  "secgensbom_out")
    _opt_row(ft, "--report-dir", "", "PATH", "Директория для отчётов",          "REPORTS_DIR", "secgensbom_reports")
    _opt_row(ft, "--verbose",    "-v", "",   "Подробный вывод",                 "",            "false")
    console.print(Panel(ft, title="[dim] format [/dim]", border_style="bright_black", padding=(0, 1)))

    # ── verify / info / status / diff ─────────────────────────────────────────
    si_t = _opts_table()
    _opt_row(si_t, "verify [dim]<файл>[/dim]", "", "", "Проверяет SHA-256 подпись — файл не изменялся / был изменён", "", "")
    _opt_row(si_t, "info [dim]<файл>[/dim]",   "", "", "Метаданные, компоненты, топ CVE по severity",             "", "")
    _opt_row(si_t, "status",                   "", "", "Версии и доступность инструментов в окружении",           "", "")
    _opt_row(si_t, "diff [dim]<a> <b>[/dim]",  "", "", "Diff компонентов и CVE между двумя SBOM",                 "", "")
    console.print(Panel(si_t, title="[dim] verify / info / status / diff [/dim]", border_style="bright_black", padding=(0, 1)))

    # ── глобальные флаги ──────────────────────────────────────────────────────
    gt = _opts_table()
    _opt_row(gt, "--version", "-V", "", "Версия инструмента и выход", "", "")
    _opt_row(gt, "--help",    "-h", "", "Показать эту справку",       "", "")
    console.print(Panel(gt, title="[dim] глобальные флаги [/dim]", border_style="bright_black", padding=(0, 1)))


# ---------------------------------------------------------------------------
# run — полный пайплайн
# ---------------------------------------------------------------------------

@app.command("run", context_settings={"help_option_names": ["-h", "--help"]})
def cmd_run(
    source: str = typer.Option(
        "local", "--source", "-s",
        help="Источник: local | github | gitlab",
        envvar="SOURCE",
    ),
    path: Optional[Path] = typer.Option(
        None, "--path",
        help="Путь к локальному проекту (по умолчанию: examples/project_inject)",
        envvar="PROJECT_DIR",
    ),
    url: Optional[str] = typer.Option(
        None, "--url",
        help="URL репозитория GitHub/GitLab",
        envvar="GIT_URL",
    ),
    token: Optional[str] = typer.Option(
        None, "--token",
        help="Токен доступа: GitHub (ghp_...) или GitLab (glpat-...)",
        envvar="GIT_TOKEN",
    ),
    branch: Optional[str] = typer.Option(
        None, "--branch",
        help="Ветка (по умолчанию HEAD)",
        envvar="GIT_BRANCH",
    ),
    output_dir: Path = typer.Option(
        Path("secgensbom_out"), "--output-dir", "-o",
        help="Директория артефактов",
        envvar="OUTPUT_DIR",
    ),
    reports_dir: Path = typer.Option(
        Path("secgensbom_reports"), "--reports-dir",
        help="Директория отчётов",
        envvar="REPORTS_DIR",
    ),
    image_name: Optional[str] = typer.Option(
        None, "--image",
        help="Docker-образ для сканирования Clair",
        envvar="IMAGE_NAME",
    ),
    clair_endpoint: str = typer.Option(
        "http://clair:8080", "--clair-endpoint",
        envvar="CLAIR_ENDPOINT",
    ),
    no_clair: bool = typer.Option(
        True, "--no-clair/--clair",
        help="Пропустить шаг Clair (по умолчанию: пропускать)",
        envvar="SKIP_CLAIR",
    ),
    use_bdu: bool = typer.Option(
        False, "--bdu/--no-bdu",
        help="Обогащать уязвимости идентификаторами БДУ (по умолчанию: выключено)",
        envvar="BDU",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Подробный вывод"),
) -> None:
    """Полный пайплайн: генерация SBOM → сканирование → отчёты."""
    _print_banner()
    setup_logging(verbose)

    cfg = PipelineConfig.from_env()
    cfg.source = source
    if path:
        cfg.project_dir = path
    if url:
        cfg.git_url = url
    if token:
        cfg.git_token = token
    if branch:
        cfg.git_branch = branch
    cfg.output_dir = output_dir
    cfg.reports_dir = reports_dir
    cfg.image_name = image_name or cfg.image_name
    cfg.clair_endpoint = clair_endpoint
    cfg.skip_clair = no_clair
    cfg.use_bdu = use_bdu
    cfg.__post_init__()

    try:
        pipeline_run(cfg)
        console.print("[bold green]✓ Пайплайн завершён успешно[/bold green]")
    except Exception as e:
        console.print(f"[bold red]✗ Ошибка: {e}[/bold red]")
        raise typer.Exit(code=1)

    _print_footer()


# ---------------------------------------------------------------------------
# format — форматирование
# ---------------------------------------------------------------------------

@app.command("format", context_settings={"help_option_names": ["-h", "--help"]})
def cmd_format(
    sbom_dir: Path = typer.Option(
        Path("secgensbom_out"), "--sbom-dir",
        help="Директория с SBOM JSON",
        envvar="OUTPUT_DIR",
    ),
    report_dir: Path = typer.Option(
        Path("secgensbom_reports"), "--report-dir",
        help="Директория для отчётов",
        envvar="REPORTS_DIR",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Форматирование SBOM JSON → xlsx / docx / odt."""
    _print_banner()
    setup_logging(verbose)
    try:
        format_sboms(sbom_dir, report_dir)
        console.print("[bold green]✓ Форматирование завершено[/bold green]")
    except Exception as e:
        console.print(f"[bold red]✗ Ошибка: {e}[/bold red]")
        raise typer.Exit(code=1)
    _print_footer()


# ---------------------------------------------------------------------------
# verify — проверка подписи
# ---------------------------------------------------------------------------

@app.command("verify", context_settings={"help_option_names": ["-h", "--help"]})
def cmd_verify(
    sbom: Path = typer.Argument(..., help="Путь к SBOM JSON файлу"),
) -> None:
    """Проверка SHA-256 подписи SBOM."""
    _print_banner()
    setup_logging()
    if not sbom.exists():
        console.print(f"[bold red]✗ Файл не найден:[/bold red] {sbom}")
        console.print("  [dim]Укажите корректный путь к SBOM JSON, например: secgensbom_out/merged-bom-signed.json[/dim]")
        raise typer.Exit(code=1)
    try:
        ok = verify_sbom(sbom)
    except Exception as e:
        console.print(f"[bold red]✗ Не удалось прочитать или разобрать файл:[/bold red] {e}")
        raise typer.Exit(code=1)
    if ok:
        console.print(f"[bold green]✓ Подпись верифицирована — файл не изменялся:[/bold green] {sbom}")
    else:
        console.print(f"[bold red]✗ Подпись не совпадает — файл был изменён или подпись отсутствует:[/bold red] {sbom}")
        raise typer.Exit(code=1)
    _print_footer()


# ---------------------------------------------------------------------------
# info — инспекция SBOM
# ---------------------------------------------------------------------------

@app.command("info", context_settings={"help_option_names": ["-h", "--help"]})
def cmd_info(
    sbom: Path = typer.Argument(..., help="Путь к SBOM JSON файлу"),
) -> None:
    """Инспекция SBOM: компоненты, уязвимости, подпись, метаданные."""
    _print_banner()

    if not sbom.exists():
        console.print(f"[bold red]✗ Файл не найден:[/bold red] {sbom}")
        console.print("  [dim]Укажите корректный путь к SBOM JSON, например: secgensbom_out/merged-bom-signed.json[/dim]")
        raise typer.Exit(code=1)

    try:
        with open(sbom, encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        console.print(f"[bold red]✗ Файл повреждён или не является валидным JSON:[/bold red] {e}")
        raise typer.Exit(code=1)

    # --- Метаданные ---
    meta = data.get("metadata", {})
    timestamp = meta.get("timestamp", "—")
    component = meta.get("component", {})
    project_name = component.get("name", "—")
    sig = meta.get("signature", {})
    sig_status = "[green]✓ подписан[/green]" if sig.get("value") else "[yellow]не подписан[/yellow]"

    # --- Компоненты ---
    components = data.get("components", [])
    langs: dict[str, int] = {}
    for c in components:
        purl = c.get("purl", "")
        ecosystem = purl.split("/")[0].replace("pkg:", "") if purl else "unknown"
        langs[ecosystem] = langs.get(ecosystem, 0) + 1

    # --- Уязвимости ---
    vulns = data.get("vulnerabilities", [])
    sev_count: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for v in vulns:
        for rating in v.get("ratings", []):
            sev = rating.get("severity", "UNKNOWN").upper()
            sev_count[sev] = sev_count.get(sev, 0) + 1

    # --- Вывод ---
    info_table = Table(box=rich_box.ROUNDED, show_header=False, padding=(0, 2))
    info_table.add_column("Поле", style="bold cyan", no_wrap=True)
    info_table.add_column("Значение")

    info_table.add_row("Файл", str(sbom))
    info_table.add_row("Формат", f"{data.get('bomFormat', '—')} {data.get('specVersion', '')}")
    info_table.add_row("Проект", project_name)
    info_table.add_row("Сгенерирован", timestamp)
    info_table.add_row("Подпись (SHA-256)", sig_status)
    info_table.add_row("Компонентов", str(len(components)))
    info_table.add_row(
        "По экосистемам",
        "  ".join(f"{k}:{v}" for k, v in sorted(langs.items())),
    )
    info_table.add_row("Уязвимостей", str(len(vulns)))
    info_table.add_row(
        "По severity",
        f"[bold red]CRITICAL:{sev_count['CRITICAL']}[/bold red]  "
        f"[red]HIGH:{sev_count['HIGH']}[/red]  "
        f"[yellow]MEDIUM:{sev_count['MEDIUM']}[/yellow]  "
        f"[green]LOW:{sev_count['LOW']}[/green]  "
        f"[dim]UNKNOWN:{sev_count['UNKNOWN']}[/dim]",
    )

    # Топ-5 критических
    top_vulns = sorted(
        vulns,
        key=lambda v: (
            {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(
                (v.get("ratings") or [{}])[0].get("severity", "LOW").upper(), 4
            )
        ),
    )[:5]

    console.print(Panel(info_table, title="[bold]SBOM Info[/bold]", border_style="cyan"))

    if top_vulns:
        top_table = Table(box=rich_box.SIMPLE, show_header=True, header_style="bold cyan")
        top_table.add_column("CVE ID", no_wrap=True)
        top_table.add_column("Severity")
        top_table.add_column("Компонент")
        top_table.add_column("Score")

        _sev_color = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow",
                      "LOW": "green", "UNKNOWN": "dim"}

        for v in top_vulns:
            vid = v.get("id", "—")
            ratings = v.get("ratings") or [{}]
            sev = ratings[0].get("severity", "UNKNOWN").upper()
            score = str(ratings[0].get("score", "—"))
            affects = v.get("affects") or [{}]
            comp_ref = affects[0].get("ref", "—")
            top_table.add_row(
                vid,
                f"[{_sev_color.get(sev, 'white')}]{sev}[/{_sev_color.get(sev, 'white')}]",
                comp_ref,
                score,
            )
        console.print("\n  [bold]Топ уязвимостей:[/bold]")
        console.print(top_table)

    _print_footer()


# ---------------------------------------------------------------------------
# status — проверка окружения
# ---------------------------------------------------------------------------

@app.command("status", context_settings={"help_option_names": ["-h", "--help"]})
def cmd_status() -> None:
    """Проверка доступности внешних инструментов."""
    _print_banner()

    def _check(cmd: list[str]) -> str:
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            line = (out.stdout or out.stderr or "").strip().splitlines()
            return line[0] if line else "ОК"
        except FileNotFoundError:
            return "__not_found__"
        except Exception as e:
            return f"ошибка: {e}"

    checks = [
        ("Python",       [sys.executable, "--version"]),
        ("pip",          [sys.executable, "-m", "pip", "--version"]),
        ("Trivy",        ["trivy", "--version"]),
        ("Docker",       ["docker", "--version"]),
        ("Node.js",      ["node", "--version"]),
        ("npx",          ["npx", "--version"]),
        ("cyclonedx-py", [sys.executable, "-m", "cyclonedx", "--version"]),
    ]

    t = Table(box=rich_box.ROUNDED, show_header=True, header_style="bold cyan", padding=(0, 2))
    t.add_column("Инструмент", style="bold", no_wrap=True)
    t.add_column("Статус")
    t.add_column("Версия / Детали")

    _install_hints: dict[str, str] = {
        "Trivy":        "brew install trivy  /  https://aquasecurity.github.io/trivy",
        "Docker":       "https://docs.docker.com/get-docker/",
        "Node.js":      "brew install node  /  https://nodejs.org",
        "npx":          "входит в состав Node.js",
        "cyclonedx-py": "pip install cyclonedx-bom",
    }

    for name, cmd in checks:
        result = _check(cmd)
        if result == "__not_found__":
            hint = _install_hints.get(name, "")
            hint_str = f"[dim]установка: {hint}[/dim]" if hint else "—"
            t.add_row(name, "[bold red]✗ не найден[/bold red]", hint_str)
        else:
            t.add_row(name, "[bold green]✓ доступен[/bold green]", result)

    console.print(Panel(t, title="[bold]Статус окружения[/bold]", border_style="cyan"))
    _print_footer()


# ---------------------------------------------------------------------------
# diff — сравнение двух SBOM
# ---------------------------------------------------------------------------

@app.command("diff", context_settings={"help_option_names": ["-h", "--help"]})
def cmd_diff(
    old: Path = typer.Argument(..., help="Старый SBOM JSON"),
    new: Path = typer.Argument(..., help="Новый SBOM JSON"),
) -> None:
    """Сравнение двух SBOM: компоненты и уязвимости."""
    _print_banner()

    for p in (old, new):
        if not p.exists():
            console.print(f"[bold red]✗ Файл не найден:[/bold red] {p}")
            console.print("  [dim]Проверьте пути к обоим SBOM JSON-файлам[/dim]")
            raise typer.Exit(code=1)

    try:
        with open(old, encoding="utf-8") as f:
            old_data = json.load(f)
        with open(new, encoding="utf-8") as f:
            new_data = json.load(f)
    except json.JSONDecodeError as e:
        console.print(f"[bold red]✗ Один из файлов повреждён или не является валидным JSON:[/bold red] {e}")
        raise typer.Exit(code=1)

    def _comp_key(c: dict) -> str:
        return c.get("purl") or f"{c.get('name', '')}@{c.get('version', '')}"

    def _vuln_key(v: dict) -> str:
        return v.get("id", "")

    old_comps = {_comp_key(c): c for c in old_data.get("components", [])}
    new_comps = {_comp_key(c): c for c in new_data.get("components", [])}
    old_vulns = {_vuln_key(v): v for v in old_data.get("vulnerabilities", [])}
    new_vulns = {_vuln_key(v): v for v in new_data.get("vulnerabilities", [])}

    added_comps   = set(new_comps) - set(old_comps)
    removed_comps = set(old_comps) - set(new_comps)
    new_cves      = set(new_vulns) - set(old_vulns)
    fixed_cves    = set(old_vulns) - set(new_vulns)

    # --- Компоненты ---
    comp_table = Table(box=rich_box.SIMPLE, show_header=True, header_style="bold cyan")
    comp_table.add_column("Статус", no_wrap=True)
    comp_table.add_column("Компонент (PURL)")

    for key in sorted(added_comps):
        comp_table.add_row("[bold green]+ добавлен[/bold green]", key)
    for key in sorted(removed_comps):
        comp_table.add_row("[bold red]− удалён[/bold red]", key)
    if not added_comps and not removed_comps:
        comp_table.add_row("[dim]без изменений[/dim]", "")

    # --- Уязвимости ---
    _sev_color = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow",
                  "LOW": "green", "UNKNOWN": "dim"}

    def _sev(v: dict) -> str:
        ratings = v.get("ratings") or [{}]
        return ratings[0].get("severity", "UNKNOWN").upper()

    vuln_table = Table(box=rich_box.SIMPLE, show_header=True, header_style="bold cyan")
    vuln_table.add_column("Статус", no_wrap=True)
    vuln_table.add_column("CVE ID")
    vuln_table.add_column("Severity")

    for cve_id in sorted(new_cves):
        v = new_vulns[cve_id]
        sev = _sev(v)
        vuln_table.add_row(
            "[bold red]+ новая CVE[/bold red]",
            cve_id,
            f"[{_sev_color.get(sev, 'white')}]{sev}[/{_sev_color.get(sev, 'white')}]",
        )
    for cve_id in sorted(fixed_cves):
        v = old_vulns[cve_id]
        sev = _sev(v)
        vuln_table.add_row(
            "[bold green]✓ закрыта[/bold green]",
            cve_id,
            f"[{_sev_color.get(sev, 'white')}]{sev}[/{_sev_color.get(sev, 'white')}]",
        )
    if not new_cves and not fixed_cves:
        vuln_table.add_row("[dim]без изменений[/dim]", "", "")

    # --- Summary ---
    summary = (
        f"Компоненты:  [green]+{len(added_comps)} добавлено[/green]  "
        f"[red]-{len(removed_comps)} удалено[/red]   |   "
        f"CVE:  [red]+{len(new_cves)} новых[/red]  "
        f"[green]-{len(fixed_cves)} закрыто[/green]"
    )

    console.print(Panel(
        summary,
        title=f"[bold]Diff: [cyan]{old.name}[/cyan] → [cyan]{new.name}[/cyan][/bold]",
        border_style="cyan",
    ))
    console.print("\n  [bold]Компоненты:[/bold]")
    console.print(comp_table)
    console.print("\n  [bold]Уязвимости:[/bold]")
    console.print(vuln_table)

    _print_footer()

# ---------------------------------------------------------------------------
# cert — обогащение полями
# ---------------------------------------------------------------------------
def add_gost_cert_fields(sbom_path: Path, add_cert: bool = False) -> Path:
    """Добавить GOST поля в каждый компонент."""
    if not add_cert:
        return sbom_path
    
    import json
    import logging
    
    with open(sbom_path, 'r', encoding='utf-8') as f:
        sbom = json.load(f)
    
    components = sbom.get("components", [])
    if not components:
        return sbom_path
    
    gost_properties =[
        {"name": "GOST:attack_surface", "value": "no"},
        {"name": "GOST:security_function", "value": "no"}
    ]
    
    updated = 0
    for component in components:
        props = component.get("properties", [])
        component["properties"] = props + gost_properties
        updated += 1
    
    cert_path = Path(str(sbom_path).replace('.json', '(cert).json'))
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(cert_path, 'w', encoding='utf-8') as f:
        json.dump(sbom, f, indent=2, ensure_ascii=False)
    
    last_digit = updated % 10
    if updated > 20 and last_digit in (2, 3, 4):
        logging.info(f"GOST поля добавлены в {updated} компонента → {cert_path}")
    else:
        logging.info(f"GOST поля добавлены в {updated} компонентов → {cert_path}")
    return cert_path

@app.command("cert", context_settings={"help_option_names": ["-h", "--help"]})
def cmd_cert(
    sbom: Path = typer.Argument(None, help="Путь к SBOM JSON файлу"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Выходной файл (по умолчанию: PATH(cert).json)")
) -> None:
    """Добавление полей GOST:attack_surface, GOST:security_function во все компоненты (по умолчанию: value = "no")."""
    _print_banner()
    setup_logging()
    
    if not sbom.exists():
        console.print(f"[bold red]✗ SBOM файл не найден:[/bold red] {sbom}")
        raise typer.Exit(code=1)
    
    try:
        cert_sbom = add_gost_cert_fields(sbom, add_cert=True)
    except Exception as e:
        console.print(f"[bold red]✗ Ошибка добавления полей:[/bold red] {e}")
        raise typer.Exit(code=1)
    
    output_path = output or cert_sbom  # Используем путь из utils если --output не указан
    console.print(f"[bold green]✓ Поля успешно добавлены в properties:[/bold green] {output_path}")
    _print_footer()

# ---------------------------------------------------------------------------
# Точка входа
# ---------------------------------------------------------------------------

def main() -> None:
    # Перехватываем secsbom / secsbom --help / secsbom -h до Click
    if len(sys.argv) == 1 or (len(sys.argv) == 2 and sys.argv[1] in ("--help", "-h")):
        _print_banner()
        _print_help_table()
        _print_footer()
        sys.exit(0)
    app()


if __name__ == "__main__":
    main()
