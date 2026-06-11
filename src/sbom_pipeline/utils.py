"""Вспомогательные утилиты."""

import logging
import os
from urllib.parse import urlparse, urlunparse

from .constants import SOURCE_TYPE_GITLAB, SOURCE_TYPE_GITHUB


def clean_git_url(url: str) -> str:
    """Нормализовать git URL для запросов к API."""
    if not url:
        return url

    if url.endswith(".git"):
        url = url[:-4]

    if url.startswith("git@"):
        url = url.split(":")[-1]

    if url.startswith("git+ssh://git@"):
        url = url.split("git@github.com/")[-1]

    parsed = urlparse(url)

    if parsed.scheme == "git+":
        parsed = parsed._replace(scheme="https")

    if parsed.netloc.startswith("www."):
        parsed = parsed._replace(netloc=parsed.netloc[4:])

    if parsed.netloc == "github.com":
        return parsed.path.lstrip("/")

    return urlunparse(parsed)


def detect_langs_from_file(deps_file: str) -> list[str]:
    """Определить языки по имени файла зависимостей."""
    base = os.path.basename(deps_file).lower()
    if base in ("requirements.txt", "pipfile", "poetry.lock") or base.endswith(
        ".pyproject"
    ):
        return ["Python"]
    if base in ("package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock"):
        return ["JavaScript", "Node.js"]
    if base == "pom.xml" or base.endswith(".gradle") or base.endswith(
        "build.gradle.kts"
    ):
        return ["Java"]
    if base.endswith(".csproj") or base.endswith("packages.config"):
        return ["C#", ".NET"]
    if base.endswith("go.mod"):
        return ["Go"]
    if base in ("composer.json", "composer.lock"):
        return ["PHP"]
    if base.endswith("cargo.toml"):
        return ["Rust"]
    return []


def setup_logging(verbose: bool = False, log_file: str = "sbom_pipeline.log") -> None:
    """Настроить логирование."""
    level = logging.DEBUG if verbose else logging.INFO
    fmt = "%(asctime)s [%(levelname)s] %(message)s"
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    try:
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))
    except OSError:
        pass
    logging.basicConfig(format=fmt, level=level, handlers=handlers, force=True)

def detect_git_service(url: str) -> str :
    domain = urlparse(url).netloc.lower()

    if "gitlab" in domain:
        return SOURCE_TYPE_GITLAB
    elif "github" in domain:
        return SOURCE_TYPE_GITHUB

    raise ValueError(f"Неизвестный git-сервис в URL: {url!r}. Поддерживаются github и gitlab.")