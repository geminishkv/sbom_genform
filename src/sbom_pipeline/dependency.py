"""Обработка зависимостей: PURL → язык + источник."""

import logging
import os
from typing import Optional

import requests
from bs4 import BeautifulSoup
from packageurl import PackageURL

from .utils import clean_git_url

_DepsMemory: list = []


class Dependency:
    def __init__(
        self,
        name: str,
        version: str,
        depType: list,
        purl: str,
        pathToSbom: str,
        package_type: str = "",
        attack_surface: str = "",
        security_function: str = "",
        container_image: str = "",
        container_role: str = "",
        os_distribution: str = "",
    ) -> None:
        self.name = name
        self.version = version
        self.srcLangs: list[str] = []
        self.source: Optional[str] = None
        self.depType = depType
        self.purl = purl
        self.pathToSbom = pathToSbom
        self.package_type = package_type
        self.attack_surface = attack_surface
        self.security_function = security_function
        self.container_image = container_image
        self.container_role = container_role
        self.os_distribution = os_distribution

        logging.debug(f"Обработка зависимости: {name} {version}")

        if self not in _DepsMemory:
            try:
                self._process_purl(purl)
            except Exception as e:
                logging.exception(f"processPurl ошибка для {purl}: {e}")
            _DepsMemory.append(self)
        else:
            cached = _DepsMemory[_DepsMemory.index(self)]
            self.srcLangs = cached.srcLangs
            self.source = cached.source

    # ------------------------------------------------------------------
    # Обработка по типу PURL
    # ------------------------------------------------------------------

    def _process_purl(self, purl: str) -> None:
        if not purl:
            return
        try:
            p = PackageURL.from_string(purl)
        except Exception as e:
            logging.warning(f"Не удалось разобрать PURL {purl}: {e}")
            return

        # Внутренний ресурс
        if "ebp" in purl or "lanit" in purl:
            self._handle_internal(p)
            return

        handlers = {
            "maven": self._process_maven,
            "pypi": self._process_pypi,
            "npm": self._process_npm,
            "deb": self._process_deb,
            "nuget": self._process_nuget,
            "composer": self._process_composer,
        }
        handler = handlers.get(p.type)
        if handler:
            handler(p)
        else:
            logging.debug(f"Неизвестный тип PURL: {p.type}")

    def _handle_internal(self, p: PackageURL) -> None:
        group = p.namespace.replace(".", "/") if p.namespace else p.name
        type_map = {
            "maven": (["Java"], f"https://INNER-RESOURCE/{group}/{p.name}/{p.version}/{p.name}-{p.version}.jar"),
            "pypi": (["Python"], f"https://INNER-RESOURCE/{p.name}/{p.version}/"),
            "npm": (["JavaScript"], f"https://INNER-RESOURCE/{group}/{p.name}/v/{p.version}"),
        }
        langs, src = type_map.get(p.type, ([], None))
        self.srcLangs, self.source = langs, src

    def _process_maven(self, p: PackageURL) -> None:
        group = p.namespace.replace(".", "/") if p.namespace else p.name
        self.srcLangs = ["Java"]
        self.source = f"https://repo1.maven.org/maven2/{group}/{p.name}/{p.version}/{p.name}-{p.version}.jar"

    def _process_pypi(self, p: PackageURL) -> None:
        self.srcLangs = ["Python"]
        self.source = f"https://pypi.org/project/{p.name}/{p.version}/"

    def _process_composer(self, p: PackageURL) -> None:
        self.srcLangs = ["PHP"]
        ns = p.namespace or ""
        self.source = f"https://packagist.org/packages/{ns}/{p.name}" if ns else f"https://packagist.org/packages/{p.name}"

    def _process_deb(self, p: PackageURL) -> None:
        url = f"https://tracker.debian.org/pkg/{p.name}"
        try:
            resp = requests.get(url, timeout=10)
            self.source = url if resp.status_code == 200 else None
        except Exception:
            self.source = None
        self.srcLangs = ["C"]

    def _process_nuget(self, p: PackageURL) -> None:
        pkg_url = f"https://www.nuget.org/packages/{p.name}/{p.version}"
        try:
            resp = requests.get(pkg_url, timeout=10)
            if resp.status_code != 200:
                self.srcLangs, self.source = ["NUGET check manually"], pkg_url
                return
            soup = BeautifulSoup(resp.text, "html.parser")
            link = (
                soup.find(attrs={"data-track": "outbound-repository-url"})
                or soup.find(attrs={"data-track": "outbound-project-url"})
            )
            if link and link.get("href") and "github.com" in link["href"]:
                href = str(link["href"])
                langs = self._fetch_github_langs(clean_git_url(href))
                self.srcLangs = langs or ["NUGET check manually"]
                self.source = href
            else:
                self.srcLangs, self.source = ["NUGET check manually"], pkg_url
        except Exception as e:
            logging.warning(f"NuGet {p.name}: {e}")
            self.srcLangs, self.source = ["NUGET check manually"], pkg_url

    def _process_npm(self, p: PackageURL) -> None:
        ns = p.namespace
        if ns:
            api_url = f"https://registry.npmjs.com/{ns}/{p.name}/{p.version}"
            pkg_url = f"https://www.npmjs.com/package/{ns}/{p.name}/v/{p.version}"
        else:
            api_url = f"https://registry.npmjs.com/{p.name}/{p.version}"
            pkg_url = f"https://www.npmjs.com/package/{p.name}/v/{p.version}"

        try:
            resp = requests.get(api_url, timeout=10)
            if resp.status_code != 200:
                self.srcLangs, self.source = ["JavaScript*"], pkg_url
                return
            content = resp.json()
            repo_url = (content.get("repository") or {}).get("url", "")
            if repo_url and "github.com" in repo_url:
                langs = self._fetch_github_langs(clean_git_url(repo_url))
                self.srcLangs = langs or ["JavaScript*"]
            else:
                self.srcLangs = ["JavaScript*"]
            self.source = pkg_url
        except Exception as e:
            logging.warning(f"NPM {p.name}: {e}")
            self.srcLangs, self.source = ["JavaScript*"], pkg_url

    def _fetch_github_langs(self, repo_path: str) -> list[str]:
        token = os.getenv("GITHUB_TOKEN")
        headers = {"Accept": "application/vnd.github+json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        try:
            resp = requests.get(
                f"https://api.github.com/repos/{repo_path}/languages",
                headers=headers,
                timeout=10,
            )
            if resp.status_code == 200:
                return list(resp.json().keys())
        except Exception:
            pass
        return []

    # ------------------------------------------------------------------

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Dependency):
            return NotImplemented
        return (self.name, self.version, self.purl) == (other.name, other.version, other.purl)

    def __hash__(self) -> int:
        return hash((self.name, self.version, self.purl))
