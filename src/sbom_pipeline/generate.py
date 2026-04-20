"""Генерация и объединение SBOM из локальной директории или Git-репозитория."""

from __future__ import annotations

import copy
import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Optional, Sequence

from .constants import CYCLONEDX_SPEC_VERSION
from .sbom_handler import SbomHandler


def _detect_project_type(project_dir: Path) -> str:
    """Определить тип проекта по манифестам."""
    checks: list[tuple[str, str]] = [
        ("requirements.txt", "python"),
        ("pyproject.toml", "python"),
        ("Pipfile", "python"),
        ("poetry.lock", "python"),
        ("package.json", "nodejs"),
        ("pom.xml", "java"),
        ("build.gradle", "java"),
        ("composer.json", "php"),
        ("go.mod", "go"),
        ("Cargo.toml", "rust"),
    ]
    for filename, lang in checks:
        if (project_dir / filename).exists():
            return lang
    return "unknown"


def generate_from_dir(
    project_dir: Path,
    output_file: Path,
    *,
    use_cdxgen: bool = True,
    use_syft: bool = True,
    cdxgen_output: Optional[Path] = None,
    syft_output: Optional[Path] = None,
) -> Path:
    """
    Сгенерировать объединённый SBOM из локальной директории.

    Стратегия:
    1. Сформировать CycloneDX SBOM через cdxgen и/или syft.
    2. Сохранить отдельные артефакты каждого генератора.
    3. Объединить результаты в единый CycloneDX JSON.
    """
    if not use_cdxgen and not use_syft:
        raise ValueError("Нужно включить хотя бы один генератор SBOM: cdxgen или syft.")

    output_file.parent.mkdir(parents=True, exist_ok=True)

    project_type = _detect_project_type(project_dir)
    logging.info(f"[generate] Тип проекта: {project_type} в {project_dir}")

    generated_files: list[tuple[str, Path]] = []
    errors: list[str] = []

    if use_cdxgen:
        cdxgen_target = cdxgen_output or _tool_output_path(output_file, "cdxgen")
        try:
            generated_files.append(("cdxgen", _generate_cdxgen_sbom(project_dir, cdxgen_target)))
        except Exception as exc:
            message = f"cdxgen: {exc}"
            logging.warning(f"[generate] {message}")
            errors.append(message)

    if use_syft:
        syft_target = syft_output or _tool_output_path(output_file, "syft")
        try:
            generated_files.append(("syft", _generate_syft_sbom(project_dir, syft_target)))
        except Exception as exc:
            message = f"syft: {exc}"
            logging.warning(f"[generate] {message}")
            errors.append(message)

    if not generated_files and project_type == "python" and shutil.which("cyclonedx-py"):
        fallback_target = _tool_output_path(output_file, "cyclonedx-py")
        result = _generate_python_sbom(project_dir, fallback_target)
        if result is not None:
            generated_files.append(("cyclonedx-py", result))
            logging.warning(
                "[generate] cdxgen/syft недоступны, использован резервный генератор cyclonedx-py"
            )

    if not generated_files:
        details = (
            "\n".join(f"- {error}" for error in errors)
            if errors
            else "- генераторы отключены"
        )
        raise RuntimeError(
            "Не удалось сформировать SBOM ни одним генератором.\n"
            "Проверьте наличие cdxgen/syft или включите нужный генератор.\n"
            f"{details}"
        )

    merged_sbom = _merge_generated_sboms(generated_files)
    SbomHandler.write_json(merged_sbom, output_file)
    logging.info(
        "[generate] Объединённый SBOM (%s) → %s",
        ", ".join(name for name, _ in generated_files),
        output_file,
    )
    return output_file


def _generate_python_sbom(project_dir: Path, output_file: Path) -> Optional[Path]:
    """Использовать cyclonedx-py как резервный генератор для Python-проектов."""
    for req_file in ("requirements.txt", "Pipfile", "poetry.lock"):
        req_path = project_dir / req_file
        if not req_path.exists():
            continue
        cmd = [
            "cyclonedx-py",
            "requirements",
            str(req_path),
            "--output-format",
            "JSON",
            "--output-file",
            str(output_file),
        ]
        logging.info(f"[generate] cyclonedx-py: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0 and output_file.exists():
            logging.info(f"[generate] cyclonedx-py SBOM → {output_file}")
            return output_file
        logging.warning(f"[generate] cyclonedx-py stderr: {result.stderr[:300]}")
    return None


def _generate_cdxgen_sbom(project_dir: Path, output_file: Path) -> Path:
    """Использовать cdxgen (npx) — универсальный генератор."""
    npx = shutil.which("npx")
    if not npx:
        raise RuntimeError(
            "npx не найден. Установите Node.js и npm, либо используйте Docker-образ."
        )

    cmd = [
        npx,
        "--yes",
        "@cyclonedx/cdxgen",
        "--spec-version",
        CYCLONEDX_SPEC_VERSION,
        "--no-bom-url",
        "--output",
        str(output_file),
        str(project_dir),
    ]
    logging.info(f"[generate] cdxgen: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        raise RuntimeError(f"cdxgen завершился с ошибкой:\n{result.stderr}")

    logging.info(f"[generate] cdxgen SBOM → {output_file}")
    return output_file


def _generate_syft_sbom(project_dir: Path, output_file: Path) -> Path:
    """Использовать syft для генерации CycloneDX JSON."""
    syft = shutil.which("syft")
    if not syft:
        raise RuntimeError("syft не найден. Установите Syft и повторите запуск.")

    attempts = [
        [syft, "scan", str(project_dir), "-o", f"cyclonedx-json={output_file}"],
        [syft, "scan", f"dir:{project_dir}", "-o", f"cyclonedx-json={output_file}"],
        [syft, str(project_dir), "-o", f"cyclonedx-json={output_file}"],
        [syft, f"dir:{project_dir}", "-o", f"cyclonedx-json={output_file}"],
    ]
    errors: list[str] = []

    for cmd in attempts:
        logging.info(f"[generate] syft: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0 and output_file.exists():
            logging.info(f"[generate] syft SBOM → {output_file}")
            return output_file

        stderr = (result.stderr or result.stdout or "").strip()
        if stderr:
            errors.append(stderr.splitlines()[0][:300])

    error_suffix = (
        "\n".join(f"- {message}" for message in errors)
        if errors
        else "- подробности недоступны"
    )
    raise RuntimeError(f"syft завершился с ошибкой:\n{error_suffix}")


def _tool_output_path(output_file: Path, tool_name: str) -> Path:
    return output_file.with_name(f"{output_file.stem}-{tool_name}{output_file.suffix}")


def _merge_generated_sboms(generated_files: Sequence[tuple[str, Path]]) -> dict[str, Any]:
    documents = [
        (generator, _mark_generator_origin(_load_sbom(path), generator))
        for generator, path in generated_files
    ]

    primary_index = next((idx for idx, (name, _) in enumerate(documents) if name == "cdxgen"), 0)
    merged = copy.deepcopy(documents[primary_index][1])

    merged["components"] = []
    merged["dependencies"] = []
    merged["services"] = []
    merged["compositions"] = []

    for _, sbom in documents:
        components = sbom.get("components", [])
        if isinstance(components, list):
            merged["components"].extend(copy.deepcopy(components))

        dependencies = sbom.get("dependencies", [])
        if isinstance(dependencies, list):
            merged["dependencies"] = _merge_dependencies(merged["dependencies"], dependencies)

        for section in ("services", "compositions"):
            items = sbom.get(section, [])
            if isinstance(items, list):
                merged[section] = _merge_unique_json_items(merged[section], items)

        metadata = sbom.get("metadata")
        if isinstance(metadata, dict):
            merged["metadata"] = _merge_metadata(merged.get("metadata", {}), metadata)

    for section in ("dependencies", "services", "compositions"):
        if not merged.get(section):
            merged.pop(section, None)

    return merged


def _merge_metadata(target: dict[str, Any], source: dict[str, Any]) -> dict[str, Any]:
    merged = copy.deepcopy(target)

    for field in (
        "timestamp",
        "component",
        "supplier",
        "manufacture",
        "authors",
        "licenses",
        "lifecycles",
    ):
        source_value = source.get(field)
        if not source_value:
            continue

        if field in ("authors", "licenses", "lifecycles"):
            merged[field] = _merge_unique_json_items(merged.get(field, []), source_value)
            continue

        if not merged.get(field):
            merged[field] = copy.deepcopy(source_value)

    merged["properties"] = _merge_named_properties(
        merged.get("properties", []),
        source.get("properties", []),
    )
    if not merged["properties"]:
        merged.pop("properties", None)

    if not merged.get("tools") and source.get("tools"):
        merged["tools"] = copy.deepcopy(source["tools"])

    return merged


def _merge_named_properties(
    target_props: list[dict[str, Any]] | Any,
    source_props: list[dict[str, Any]] | Any,
) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = (
        copy.deepcopy(target_props) if isinstance(target_props, list) else []
    )
    by_name = {
        prop.get("name", ""): prop
        for prop in merged
        if isinstance(prop, dict) and prop.get("name")
    }

    for prop in source_props if isinstance(source_props, list) else []:
        if not isinstance(prop, dict):
            continue
        prop_name = prop.get("name", "")
        if not prop_name:
            continue
        if prop_name not in by_name:
            cloned = copy.deepcopy(prop)
            merged.append(cloned)
            by_name[prop_name] = cloned
        elif not by_name[prop_name].get("value") and prop.get("value"):
            by_name[prop_name]["value"] = prop["value"]

    return merged


def _merge_dependencies(
    target_deps: list[dict[str, Any]],
    source_deps: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    by_ref: dict[str, dict[str, Any]] = {}
    seen_no_ref: set[str] = set()

    for dep in list(target_deps) + list(source_deps):
        if not isinstance(dep, dict):
            continue

        dep_ref = dep.get("ref")
        if not dep_ref:
            dep_key = json.dumps(dep, sort_keys=True, ensure_ascii=False)
            if dep_key not in seen_no_ref:
                merged.append(copy.deepcopy(dep))
                seen_no_ref.add(dep_key)
            continue

        current = by_ref.get(dep_ref)
        if current is None:
            current = {"ref": dep_ref}
            merged.append(current)
            by_ref[dep_ref] = current

        for key, value in dep.items():
            if key == "dependsOn" and isinstance(value, list):
                current_deps = current.setdefault("dependsOn", [])
                for ref in value:
                    if ref not in current_deps:
                        current_deps.append(ref)
            elif key not in current and value:
                current[key] = copy.deepcopy(value)

    return merged


def _merge_unique_json_items(target: list[Any], source: list[Any]) -> list[Any]:
    merged = copy.deepcopy(target)
    seen = {json.dumps(item, sort_keys=True, ensure_ascii=False) for item in merged}

    for item in source:
        key = json.dumps(item, sort_keys=True, ensure_ascii=False)
        if key not in seen:
            merged.append(copy.deepcopy(item))
            seen.add(key)

    return merged


def _mark_generator_origin(sbom: dict[str, Any], generator: str) -> dict[str, Any]:
    marked = copy.deepcopy(sbom)
    property_name = f"sbom_pipeline:generator:{generator}"

    metadata = marked.setdefault("metadata", {})
    if isinstance(metadata, dict):
        _append_property(metadata, property_name, "true")

    for component in marked.get("components", []):
        if isinstance(component, dict):
            _append_property(component, property_name, "true")

    return marked


def _append_property(target: dict[str, Any], name: str, value: str) -> None:
    properties = target.setdefault("properties", [])
    if not isinstance(properties, list):
        properties = []
        target["properties"] = properties

    if any(
        isinstance(prop, dict) and prop.get("name") == name and prop.get("value") == value
        for prop in properties
    ):
        return

    properties.append({"name": name, "value": value})


def _load_sbom(path: Path) -> dict[str, Any]:
    with open(path, encoding="utf-8") as file_obj:
        return json.load(file_obj)


def generate_from_git(
    url: str,
    output_file: Path,
    token: Optional[str] = None,
    branch: Optional[str] = None,
    *,
    use_cdxgen: bool = True,
    use_syft: bool = True,
    cdxgen_output: Optional[Path] = None,
    syft_output: Optional[Path] = None,
) -> Path:
    """
    Клонировать Git-репозиторий (GitHub / GitLab) и сгенерировать SBOM.

    Токен встраивается в URL как oauth2-заголовок, что поддерживается
    обоими платформами (GitHub: ghp_... / GitLab: glpat-...).
    """
    import git as gitpy

    from urllib.parse import urlparse, urlunparse

    clone_url = url
    if token:
        parsed = urlparse(url)
        netloc = f"oauth2:{token}@{parsed.netloc}"
        clone_url = urlunparse(parsed._replace(netloc=netloc))

    with tempfile.TemporaryDirectory(prefix="sbom_clone_") as tmpdir:
        clone_dir = Path(tmpdir) / "repo"
        logging.info(f"[generate] Клонирование {url} ...")
        kwargs: dict[str, Any] = {"depth": 1}
        if branch:
            kwargs["branch"] = branch
        gitpy.Repo.clone_from(clone_url, clone_dir, **kwargs)
        logging.info(f"[generate] Клонировано в {clone_dir}")
        return generate_from_dir(
            clone_dir,
            output_file,
            use_cdxgen=use_cdxgen,
            use_syft=use_syft,
            cdxgen_output=cdxgen_output,
            syft_output=syft_output,
        )
