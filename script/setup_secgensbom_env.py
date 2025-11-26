#!/usr/bin/env python3
import os
from pathlib import Path

def main() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    project_inject = repo_root / "project_inject"
    secgensbom_out = repo_root / "secgensbom_out"
    depcheck_dir = secgensbom_out / "dependency-check"
    trivy_dir = secgensbom_out / "trivy"
    depcheck_data = repo_root / ".dependency-check-data"

    for d in [project_inject, secgensbom_out, depcheck_dir, trivy_dir, depcheck_data]:
        d.mkdir(parents=True, exist_ok=True)

    # Печатаем пути в формате KEY=VALUE (без export)
    print(f"HOST_PROJECT_DIR={project_inject.resolve()}")
    print(f"HOST_OUTPUT_DIR={secgensbom_out.resolve()}")
    print(f"HOST_DEP_REPORT_DIR={depcheck_dir.resolve()}")
    print(f"HOST_TRIVY_REPORT_DIR={trivy_dir.resolve()}")
    print(f"DEP_CHECK_DATA={depcheck_data.resolve()}")

if __name__ == "__main__":
    main()
