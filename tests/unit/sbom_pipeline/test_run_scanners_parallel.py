"""Unit tests for pipeline._run_scanners_parallel."""

from __future__ import annotations

import threading
import time
from typing import List
from unittest.mock import patch

import pytest

from sbom_pipeline.pipeline import _run_scanners_parallel
from sbom_pipeline.vuln_merger import VulnFinding


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _finding(cve_id: str = 'CVE-2024-0001', scanner: str = 'trivy') -> VulnFinding:
    return VulnFinding(
        cve_id=cve_id,
        component_name='requests',
        component_version='2.31.0',
        component_purl='pkg:pypi/requests@2.31.0',
        cvss_score=7.5,
        severity='HIGH',
        description='Test',
        scanner=scanner,
    )


# ===========================================================================
# Basic behaviour
# ===========================================================================

class TestRunScannerParallelBasic:
    def test_empty_task_list_returns_empty(self):
        assert _run_scanners_parallel([]) == []

    def test_single_task_returns_its_findings(self):
        f = _finding('CVE-2024-0001')
        result = _run_scanners_parallel([('t1', lambda: [f])])
        assert result == [f]

    def test_multiple_tasks_results_are_combined(self):
        f1 = _finding('CVE-2024-0001', scanner='trivy')
        f2 = _finding('CVE-2024-0002', scanner='depcheck')
        f3 = _finding('CVE-2024-0003', scanner='clair')

        result = _run_scanners_parallel([
            ('trivy', lambda: [f1]),
            ('depcheck', lambda: [f2]),
            ('clair', lambda: [f3]),
        ])

        cve_ids = {f.cve_id for f in result}
        assert cve_ids == {'CVE-2024-0001', 'CVE-2024-0002', 'CVE-2024-0003'}
        assert len(result) == 3

    def test_task_returning_empty_list_does_not_add_findings(self):
        f = _finding()
        result = _run_scanners_parallel([
            ('populated', lambda: [f]),
            ('empty', lambda: []),
        ])
        assert len(result) == 1

    def test_total_finding_count_is_sum_of_all_tasks(self):
        tasks = [('t' + str(i), lambda i=i: [_finding(f'CVE-2024-{i:04d}')]) for i in range(5)]
        result = _run_scanners_parallel(tasks)
        assert len(result) == 5


# ===========================================================================
# Exception handling
# ===========================================================================

class TestRunScannerParallelExceptions:
    def test_exception_in_one_task_does_not_prevent_others(self):
        f = _finding('CVE-2024-GOOD')

        def failing():
            raise RuntimeError('scanner exploded')

        result = _run_scanners_parallel([
            ('good', lambda: [f]),
            ('bad', failing),
        ])

        assert any(x.cve_id == 'CVE-2024-GOOD' for x in result)

    def test_exception_in_all_tasks_returns_empty_list(self):
        def fail():
            raise RuntimeError('boom')

        result = _run_scanners_parallel([('a', fail), ('b', fail), ('c', fail)])
        assert result == []

    def test_exception_in_task_is_logged_as_error(self, caplog):
        import logging

        def fail():
            raise ValueError('scan failed')

        with caplog.at_level(logging.ERROR):
            _run_scanners_parallel([('bad-scanner', fail)])

        assert any('bad-scanner' in r.message for r in caplog.records)
        assert any(r.levelname == 'ERROR' for r in caplog.records)


# ===========================================================================
# Concurrency
# ===========================================================================

class TestRunScannerParallelConcurrency:
    def test_tasks_run_concurrently(self):
        """All N tasks must overlap in time — verified via a threading.Barrier.

        If tasks ran serially, the barrier.wait() call inside each task would
        time out (the last task would never arrive while the first is blocked).
        """
        n = 3
        barrier = threading.Barrier(n, timeout=5)

        def concurrent_task():
            barrier.wait()  # raises BrokenBarrierError if not all n threads arrive
            return [_finding()]

        tasks = [(f't{i}', concurrent_task) for i in range(n)]
        result = _run_scanners_parallel(tasks)
        assert len(result) == n

    def test_slow_task_does_not_block_fast_tasks(self):
        """Findings from fast tasks must be available even if one task is slow."""
        fast_done = threading.Event()

        def slow():
            fast_done.wait(timeout=5)  # wait until the fast task is known to have run
            return [_finding('CVE-SLOW')]

        def fast():
            fast_done.set()
            return [_finding('CVE-FAST')]

        result = _run_scanners_parallel([('slow', slow), ('fast', fast)])
        cve_ids = {f.cve_id for f in result}
        assert cve_ids == {'CVE-SLOW', 'CVE-FAST'}
