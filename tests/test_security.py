"""Регрессионные тесты для фиксов security-аудита (SEC-001…SEC-007)."""

from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# SEC-004 — валидация схемы CLAIR_ENDPOINT (CWE-918/22, запрет file:// и пр.)
# ---------------------------------------------------------------------------

def test_clair_endpoint_rejects_file_scheme():
    from sbom_pipeline.config import PipelineConfig

    with pytest.raises(ValueError, match="http"):
        PipelineConfig(clair_endpoint="file:///etc/passwd")


def test_clair_endpoint_rejects_non_http_scheme():
    from sbom_pipeline.config import PipelineConfig

    with pytest.raises(ValueError):
        PipelineConfig(clair_endpoint="gopher://evil.example")


def test_clair_endpoint_accepts_http_and_https():
    from sbom_pipeline.config import PipelineConfig

    assert PipelineConfig(clair_endpoint="http://clair:8080").clair_endpoint == "http://clair:8080"
    assert PipelineConfig(clair_endpoint="https://clair:8080").clair_endpoint == "https://clair:8080"


# ---------------------------------------------------------------------------
# SEC-001 — git-токен не утекает в текст исключения (CWE-532)
# ---------------------------------------------------------------------------

def test_git_clone_error_masks_token(monkeypatch, tmp_path):
    import git as gitpy

    from sbom_pipeline import generate

    token = "ghp_SECRETTOKEN1234567890"
    url = "https://github.com/org/repo"

    def fake_clone(clone_url, clone_dir, **kwargs):
        # git-ошибка, в тексте которой фигурирует URL с встроенным токеном
        raise gitpy.GitCommandError(
            ["git", "clone", clone_url], 128, stderr=f"fatal: {clone_url} not found"
        )

    monkeypatch.setattr(gitpy.Repo, "clone_from", staticmethod(fake_clone))

    with pytest.raises(RuntimeError) as exc:
        generate.generate_from_git(url, tmp_path / "out.json", token=token)

    msg = str(exc.value)
    assert token not in msg, "Токен не должен попадать в сообщение об ошибке"
    assert "github.com/org/repo" in msg


# ---------------------------------------------------------------------------
# SEC-003 — TLS-проверка БДУ настраивается через BDU_CA_BUNDLE
# ---------------------------------------------------------------------------

def test_bdu_verify_default_disabled_without_ca_bundle():
    from sbom_pipeline.enrichters import bdu

    # В тест-окружении BDU_CA_BUNDLE не задан → проверка отключена (self-signed ФСТЭК).
    # Если переменная задана локально — это путь к CA (str), что тоже корректно.
    assert bdu.BDU_VERIFY is False or isinstance(bdu.BDU_VERIFY, str)
