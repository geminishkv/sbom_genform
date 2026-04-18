"""Конфигурация пайплайна — читается из переменных окружения / CLI."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

from .constants import (
    SBOM_OUT_DIR,
    REPORTS_DIR,
    TRIVY_DIR,
    CLAIR_DIR,
    DEPCHECK_DIR,
)

load_dotenv()


@dataclass
class PipelineConfig:
    """Конфигурация полного SBOM-пайплайна."""

    # --- Источник ---
    source: str = "local"          # local | github | gitlab
    project_dir: Path = field(default_factory=lambda: Path("examples/project_inject"))
    git_url: Optional[str] = None
    git_token: Optional[str] = None
    git_branch: Optional[str] = None

    # --- Пути ---
    output_dir: Path = field(default_factory=lambda: Path(SBOM_OUT_DIR))
    reports_dir: Path = field(default_factory=lambda: Path(REPORTS_DIR))

    # Хостовые пути (для Docker volume-маунтов)
    host_project_dir: Optional[Path] = None
    host_output_dir: Optional[Path] = None
    host_dep_report_dir: Optional[Path] = None
    host_dep_check_data: Optional[Path] = None
    host_trivy_report_dir: Optional[Path] = None
    host_clair_report_dir: Optional[Path] = None
    dep_check_data: Optional[Path] = None

    # --- NVD API ---
    nvd_api_key: Optional[str] = None

    # --- Сканирование образов ---
    image_name: Optional[str] = None
    clair_endpoint: str = "http://clair:8080"
    skip_clair: bool = True

    # --- GitHub API ---
    github_token: Optional[str] = None

    # --- Enrichment ---
    use_bdu: bool = False

    # --- Производные пути (вычисляются после init) ---
    trivy_dir: Path = field(init=False)
    clair_dir: Path = field(init=False)
    depcheck_dir: Path = field(init=False)

    def __post_init__(self) -> None:
        self.trivy_dir = self.output_dir / TRIVY_DIR
        self.clair_dir = self.output_dir / CLAIR_DIR
        self.depcheck_dir = self.output_dir / DEPCHECK_DIR

        if self.dep_check_data is None:
            self.dep_check_data = Path(".dependency-check-data")

    @classmethod
    def from_env(cls) -> "PipelineConfig":
        """Создать конфиг из переменных окружения."""

        def _path(key: str, default: Optional[str] = None) -> Optional[Path]:
            v = os.getenv(key, default)
            return Path(v) if v else None

        return cls(
            source=os.getenv("SOURCE", "local"),
            project_dir=_path("PROJECT_DIR", "examples/project_inject") or Path("examples/project_inject"),
            git_url=os.getenv("GIT_URL") or None,
            git_token=os.getenv("GIT_TOKEN") or None,
            git_branch=os.getenv("GIT_BRANCH") or None,
            output_dir=_path("OUTPUT_DIR", SBOM_OUT_DIR) or Path(SBOM_OUT_DIR),
            reports_dir=_path("REPORTS_DIR", REPORTS_DIR) or Path(REPORTS_DIR),
            host_project_dir=_path("HOST_PROJECT_DIR"),
            host_output_dir=_path("HOST_OUTPUT_DIR"),
            host_dep_report_dir=_path("HOST_DEP_REPORT_DIR"),
            host_dep_check_data=_path("HOST_DEP_CHECK_DATA"),
            host_trivy_report_dir=_path("HOST_TRIVY_REPORT_DIR"),
            host_clair_report_dir=_path("HOST_CLAIR_REPORT_DIR"),
            nvd_api_key=os.getenv("NVD_API_KEY") or None,
            dep_check_data=_path("DEP_CHECK_DATA", ".dependency-check-data"),
            image_name=os.getenv("IMAGE_NAME") or None,
            clair_endpoint=os.getenv("CLAIR_ENDPOINT", "http://clair:8080"),
            skip_clair=os.getenv("SKIP_CLAIR", "true").lower() in ("true", "1", "yes"),
            github_token=os.getenv("GITHUB_TOKEN") or None,
            use_bdu=os.getenv("BDU", "false").lower() in ("true", "1", "yes"),
        )

    def ensure_output_dirs(self) -> None:
        """Создать все выходные директории."""
        for d in (
            self.output_dir,
            self.trivy_dir,
            self.clair_dir,
            self.depcheck_dir,
            self.reports_dir,
        ):
            d.mkdir(parents=True, exist_ok=True)
