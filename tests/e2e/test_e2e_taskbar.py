"""
End-to-end Playwright tests for the TaskBar feature.

Tests the full lifecycle: task creation via API, TaskBar rendering,
progress updates, dismiss/cancel, review modal, and session isolation.

No Celery worker required — tasks are created via API and then manipulated
directly in SQLite to simulate worker progress.
"""
import json
import os
import sqlite3
import subprocess
import sys
import time
import uuid
from datetime import datetime, timedelta

import pytest
from playwright.sync_api import sync_playwright, expect

BASE_URL = "http://localhost:8788"
DB_PATH = "./data/test_e2e_taskbar.db"

# ── Fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module", autouse=True)
def start_server():
    """Start Lazeport on a dedicated port with a fresh test DB."""
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    env = os.environ.copy()
    env["AUTH_DISABLED"] = "1"
    env["DATABASE_URL"] = f"sqlite:///{DB_PATH}"
    env["SESSION_SECRET_KEY"] = "e2e-taskbar-session-key"
    env["APP_SECRET_KEY"] = "e2e-taskbar-app-key"
    env["LOG_LEVEL"] = "WARNING"
    env["RATE_LIMIT_DISABLED"] = "1"  # Bypass rate limiting for e2e tests

    proc = subprocess.Popen(
        [
            sys.executable, "-m", "uvicorn", "app.main:app",
            "--host", "0.0.0.0", "--port", "8788",
            "--log-level", "warning",
        ],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    import httpx
    for _ in range(30):
        try:
            r = httpx.get(f"{BASE_URL}/api/health", timeout=2)
            if r.status_code == 200:
                break
        except Exception:
            pass
        time.sleep(1)
    else:
        proc.kill()
        raise RuntimeError("Server did not start in time")

    yield proc

    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)


@pytest.fixture(scope="module")
def browser():
    with sync_playwright() as p:
        b = p.chromium.launch(headless=True)
        yield b
        b.close()


@pytest.fixture
def page(browser):
    ctx = browser.new_context(viewport={"width": 1280, "height": 720})
    pg = ctx.new_page()
    yield pg
    pg.close()
    ctx.close()


# ── Helpers ─────────────────────────────────────────────────────────────────


def api_post(page, path, body):
    return page.context.request.post(
        f"{BASE_URL}{path}",
        data=json.dumps(body),
        headers={"Content-Type": "application/json"},
    )


def api_get(page, path):
    return page.context.request.get(f"{BASE_URL}{path}")


def api_delete(page, path):
    return page.context.request.delete(f"{BASE_URL}{path}")


def get_user_id(page):
    """Get current user ID. Navigates to dashboard first to establish session."""
    page.goto(f"{BASE_URL}/dashboard")
    page.wait_for_load_state("networkidle")
    resp = api_get(page, "/api/me")
    assert resp.status == 200
    return resp.json()["id"]


def create_report(page):
    resp = api_post(page, "/api/admin/reports", {"name": f"TaskBar Test Report {uuid.uuid4().hex[:6]}"})
    assert resp.status == 200, f"create_report failed: {resp.status} {resp.text()}"
    return resp.json()["id"]


def create_finding(page, report_id):
    resp = api_post(page, "/api/admin/findings", {
        "report_id": report_id,
        "title": "XSS in Search Field",
        "content": {"Vulnerability Summary": "Reflected XSS", "Severity": "High"},
        "notes": "Found reflected XSS via search parameter q=<script>alert(1)</script>",
        "template": "",
    })
    assert resp.status == 200, f"create_finding failed: {resp.status} {resp.text()}"
    return resp.json()["id"]


def insert_task(user_id, report_id, *, task_type="generate_finding", status="running",
                title="Generating: XSS in Search", current_step=2, total_steps=4,
                finding_id=None, result_json="", error="", progress_log=None,
                started_minutes_ago=0):
    """Insert a GenerationTask row directly into the test DB."""
    task_id = str(uuid.uuid4())
    now = datetime.utcnow()
    started = now - timedelta(minutes=started_minutes_ago)
    finished = now if status in ("completed", "failed", "cancelled") else None
    if progress_log is None:
        progress_log = json.dumps(["Parsing notes...", "Calling LLM (gpt-4o-mini)..."])

    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """INSERT INTO generation_task
           (id, user_id, organization_id, report_id, finding_id, task_type,
            title, status, celery_task_id, current_step, total_steps,
            progress_log, result_json, error, created_at, started_at, finished_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (task_id, user_id, "default", report_id, finding_id, task_type,
         title, status, f"celery-{uuid.uuid4()}", current_step, total_steps,
         progress_log, result_json, error,
         now.isoformat(), started.isoformat(),
         finished.isoformat() if finished else None),
    )
    conn.commit()
    conn.close()
    return task_id


def update_task(task_id, **fields):
    conn = sqlite3.connect(DB_PATH)
    sets = ", ".join(f"{k} = ?" for k in fields)
    vals = list(fields.values()) + [task_id]
    conn.execute(f"UPDATE generation_task SET {sets} WHERE id = ?", vals)
    conn.commit()
    conn.close()


def delete_all_tasks():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM generation_task")
    conn.commit()
    conn.close()


def navigate_to_dashboard(page):
    """Navigate to dashboard and wait for the polling store to initialize."""
    page.goto(f"{BASE_URL}/dashboard")
    page.wait_for_load_state("networkidle")


def ensure_expanded(page):
    """Expand the TaskBar if it isn't already (handles auto-expand)."""
    strip = page.locator(".task-bar__strip")
    if strip.get_attribute("aria-expanded") != "true":
        strip.click()
        page.wait_for_timeout(500)


def ensure_collapsed(page):
    """Collapse the TaskBar if it's currently expanded."""
    strip = page.locator(".task-bar__strip")
    if strip.get_attribute("aria-expanded") == "true":
        strip.click()
        page.wait_for_timeout(500)


# ── Tests ───────────────────────────────────────────────────────────────────


class TestTaskBarRendering:
    """TaskBar appears, shows correct status, and updates via polling."""

    def test_taskbar_hidden_when_no_tasks(self, page):
        """TaskBar should not be visible when there are no tasks."""
        delete_all_tasks()
        navigate_to_dashboard(page)
        page.wait_for_timeout(3000)
        assert page.locator(".task-bar").count() == 0

    def test_taskbar_appears_for_running_task(self, page):
        """TaskBar should appear when there's a running task."""
        delete_all_tasks()
        user_id = get_user_id(page)
        report_id = create_report(page)
        insert_task(user_id, report_id, status="running", current_step=1, total_steps=4,
                    title="Generating: SQL Injection")

        navigate_to_dashboard(page)
        bar = page.locator(".task-bar")
        expect(bar).to_be_visible(timeout=5000)

        # Collapsed strip should show the task title and step count
        strip = page.locator(".task-bar__strip")
        expect(strip).to_contain_text("SQL Injection")
        expect(strip).to_contain_text("1/4")

    def test_taskbar_shows_completed_task(self, page):
        """TaskBar should show completed task with a checkmark."""
        delete_all_tasks()
        user_id = get_user_id(page)
        report_id = create_report(page)
        task_id = insert_task(user_id, report_id, status="running", current_step=3, total_steps=4)

        navigate_to_dashboard(page)
        expect(page.locator(".task-bar")).to_be_visible(timeout=5000)

        # Transition to completed
        update_task(task_id,
                    status="completed", current_step=4,
                    result_json=json.dumps({"Finding Title": "SQL Injection"}),
                    finished_at=datetime.utcnow().isoformat())

        # Wait for poll + auto-expand
        page.wait_for_timeout(5000)

        # TaskBar auto-expands on completion; ensure expanded and check
        ensure_expanded(page)
        row = page.locator(".task-bar__row").first
        expect(row).to_be_visible()
        expect(row).to_contain_text("\u2713")  # checkmark

    def test_taskbar_shows_failed_task(self, page):
        """TaskBar should show failed task with error message."""
        delete_all_tasks()
        user_id = get_user_id(page)
        report_id = create_report(page)
        task_id = insert_task(user_id, report_id, status="running", current_step=1, total_steps=4,
                              title="Generating: Broken Task")
        navigate_to_dashboard(page)
        expect(page.locator(".task-bar")).to_be_visible(timeout=5000)

        update_task(task_id, status="failed", error="LLM connection timed out",
                    finished_at=datetime.utcnow().isoformat())
        page.wait_for_timeout(5000)

        ensure_expanded(page)
        row = page.locator(".task-bar__row").first
        expect(row).to_be_visible()
        expect(row).to_contain_text("LLM connection timed out")

    def test_progress_updates_via_polling(self, page):
        """TaskBar should reflect step changes when the DB updates."""
        delete_all_tasks()
        user_id = get_user_id(page)
        report_id = create_report(page)
        task_id = insert_task(user_id, report_id, status="running", current_step=0, total_steps=4,
                              progress_log=json.dumps([]))
        navigate_to_dashboard(page)
        expect(page.locator(".task-bar")).to_be_visible(timeout=5000)

        ensure_expanded(page)

        # Update step count
        update_task(task_id, current_step=2,
                    progress_log=json.dumps(["Parsing notes...", "Calling LLM (gpt-4o-mini)..."]))
        page.wait_for_timeout(4000)

        row = page.locator(".task-bar__row").first
        expect(row).to_contain_text("2/4")

    def test_progress_message_displays(self, page):
        """TaskBar should show the latest progress message from progress_log."""
        delete_all_tasks()
        user_id = get_user_id(page)
        report_id = create_report(page)
        insert_task(user_id, report_id, status="running", current_step=2, total_steps=4,
                    progress_log=json.dumps(["Parsing notes...", "Calling LLM (gpt-4o-mini)..."]))
        navigate_to_dashboard(page)
        expect(page.locator(".task-bar")).to_be_visible(timeout=5000)

        ensure_expanded(page)
        row = page.locator(".task-bar__row").first
        expect(row).to_contain_text("Calling LLM (gpt-4o-mini)...")


class TestTaskBarInteractions:
    """Dismiss, cancel, and expand/collapse behavior."""

    def test_expand_and_collapse(self, page):
        """Clicking the strip toggles expanded state."""
        delete_all_tasks()
        user_id = get_user_id(page)
        report_id = create_report(page)
        insert_task(user_id, report_id, status="running")
        navigate_to_dashboard(page)
        expect(page.locator(".task-bar")).to_be_visible(timeout=5000)

        # Running task: bar should start collapsed (no auto-expand for running tasks)
        assert page.locator(".task-bar__list").count() == 0

        # Click to expand
        page.locator(".task-bar__strip").click()
        expect(page.locator(".task-bar__list")).to_be_visible()

        # Click again to collapse
        page.locator(".task-bar__strip").click()
        page.wait_for_timeout(300)
        assert page.locator(".task-bar__list").count() == 0

    def test_dismiss_completed_task(self, page):
        """Clicking dismiss on a completed task removes it from the bar."""
        delete_all_tasks()
        user_id = get_user_id(page)
        report_id = create_report(page)
        task_id = insert_task(user_id, report_id, status="running", current_step=3, total_steps=4)
        navigate_to_dashboard(page)
        expect(page.locator(".task-bar")).to_be_visible(timeout=5000)

        # Complete it
        update_task(task_id, status="completed", current_step=4,
                    finished_at=datetime.utcnow().isoformat(),
                    result_json=json.dumps({"text": "done"}))
        page.wait_for_timeout(5000)

        # Auto-expands on completion — ensure expanded
        ensure_expanded(page)

        # Find and click dismiss button (the X on completed tasks)
        dismiss_btns = page.locator(".task-bar__row .task-bar__cancel-btn")
        expect(dismiss_btns.first).to_be_visible(timeout=3000)
        dismiss_btns.first.click()

        # Bar should disappear (only task was dismissed)
        page.wait_for_timeout(1000)
        assert page.locator(".task-bar__row").count() == 0

    def test_cancel_running_task(self, page):
        """Cancel button on a running task sends DELETE and transitions to cancelled."""
        delete_all_tasks()
        user_id = get_user_id(page)
        report_id = create_report(page)
        task_id = insert_task(user_id, report_id, status="running", current_step=1, total_steps=4,
                              title="Generating: Cancellable Task")
        navigate_to_dashboard(page)
        expect(page.locator(".task-bar")).to_be_visible(timeout=5000)

        ensure_expanded(page)

        cancel_btn = page.locator(".task-bar__row .task-bar__cancel-btn")
        expect(cancel_btn).to_be_visible()
        cancel_btn.click()
        page.wait_for_timeout(2000)

        # API should reflect cancellation
        resp = api_get(page, f"/api/tasks/{task_id}")
        assert resp.status == 200
        assert resp.json()["status"] == "cancelled"


class TestSessionIsolation:
    """Terminal tasks from before the session should not appear."""

    def test_old_completed_task_not_shown(self, page):
        """A completed task that was never seen as running should not appear."""
        delete_all_tasks()
        user_id = get_user_id(page)
        report_id = create_report(page)
        insert_task(user_id, report_id, status="completed", current_step=4, total_steps=4,
                    result_json=json.dumps({"text": "old result"}),
                    title="Generating: Old Task")

        navigate_to_dashboard(page)
        page.wait_for_timeout(4000)
        assert page.locator(".task-bar").count() == 0

    def test_old_failed_task_not_shown(self, page):
        """A failed task from a previous session should not appear."""
        delete_all_tasks()
        user_id = get_user_id(page)
        report_id = create_report(page)
        insert_task(user_id, report_id, status="failed", current_step=1, total_steps=4,
                    error="Worker crashed", title="Generating: Crashed Task")

        navigate_to_dashboard(page)
        page.wait_for_timeout(4000)
        assert page.locator(".task-bar").count() == 0

    def test_active_task_from_previous_session_shown(self, page):
        """A still-running task should appear even on fresh page load."""
        delete_all_tasks()
        user_id = get_user_id(page)
        report_id = create_report(page)
        insert_task(user_id, report_id, status="running", current_step=2, total_steps=4,
                    title="Generating: Still Running")

        navigate_to_dashboard(page)
        bar = page.locator(".task-bar")
        expect(bar).to_be_visible(timeout=5000)
        expect(bar).to_contain_text("Still Running")


class TestStaleDetection:
    """Tasks running > 10 min should appear as stale."""

    def test_stale_task_shown_with_warning(self, page):
        """A task running > 10 min should show stale status in TaskBar."""
        delete_all_tasks()
        user_id = get_user_id(page)
        report_id = create_report(page)
        insert_task(user_id, report_id, status="running", current_step=1, total_steps=4,
                    title="Generating: Stale Task", started_minutes_ago=15)

        navigate_to_dashboard(page)
        bar = page.locator(".task-bar")
        expect(bar).to_be_visible(timeout=5000)

        # Stale tasks auto-expand (they're in doneTasks via status=stale)
        ensure_expanded(page)
        row = page.locator(".task-bar__row").first
        expect(row).to_contain_text("\u26a0")  # warning triangle

    def test_stale_task_can_be_dismissed(self, page):
        """Stale tasks should have a dismiss button."""
        delete_all_tasks()
        user_id = get_user_id(page)
        report_id = create_report(page)
        insert_task(user_id, report_id, status="running", current_step=1, total_steps=4,
                    title="Generating: Stale Dismissable", started_minutes_ago=15)

        navigate_to_dashboard(page)
        expect(page.locator(".task-bar")).to_be_visible(timeout=5000)
        ensure_expanded(page)

        dismiss_btn = page.locator(".task-bar__row .task-bar__cancel-btn")
        expect(dismiss_btn.first).to_be_visible(timeout=3000)
        dismiss_btn.first.click()
        page.wait_for_timeout(1000)
        assert page.locator(".task-bar__row").count() == 0


class TestTaskBarAPI:
    """Verify the task API endpoints work correctly for the TaskBar."""

    def test_list_tasks_returns_user_tasks(self, page):
        delete_all_tasks()
        user_id = get_user_id(page)
        report_id = create_report(page)
        task_id = insert_task(user_id, report_id, status="running")

        resp = api_get(page, "/api/tasks")
        assert resp.status == 200
        data = resp.json()
        assert "tasks" in data
        assert any(t["id"] == task_id for t in data["tasks"])

    def test_list_tasks_excludes_result_json(self, page):
        delete_all_tasks()
        user_id = get_user_id(page)
        report_id = create_report(page)
        insert_task(user_id, report_id, status="completed",
                    result_json=json.dumps({"secret": "data"}))

        resp = api_get(page, "/api/tasks")
        assert resp.status == 200
        for task in resp.json()["tasks"]:
            assert "result_json" not in task

    def test_get_single_task_includes_result(self, page):
        delete_all_tasks()
        user_id = get_user_id(page)
        report_id = create_report(page)
        task_id = insert_task(user_id, report_id, status="completed",
                              result_json=json.dumps({"Finding Title": "XSS"}))

        resp = api_get(page, f"/api/tasks/{task_id}")
        assert resp.status == 200
        data = resp.json()
        assert "result_json" in data
        assert "XSS" in data["result_json"]

    def test_cancel_task_via_api(self, page):
        delete_all_tasks()
        user_id = get_user_id(page)
        report_id = create_report(page)
        task_id = insert_task(user_id, report_id, status="running")

        resp = api_delete(page, f"/api/tasks/{task_id}")
        assert resp.status == 204

        resp = api_get(page, f"/api/tasks/{task_id}")
        assert resp.status == 200
        assert resp.json()["status"] == "cancelled"

    def test_stale_detection_in_api(self, page):
        delete_all_tasks()
        user_id = get_user_id(page)
        report_id = create_report(page)
        task_id = insert_task(user_id, report_id, status="running", started_minutes_ago=15)

        resp = api_get(page, f"/api/tasks/{task_id}")
        assert resp.status == 200
        assert resp.json()["status"] == "stale"


class TestTaskBarAccessibility:
    """Verify ARIA attributes and keyboard navigation."""

    def test_bar_has_log_role(self, page):
        delete_all_tasks()
        user_id = get_user_id(page)
        report_id = create_report(page)
        insert_task(user_id, report_id, status="running")

        navigate_to_dashboard(page)
        bar = page.locator(".task-bar")
        expect(bar).to_be_visible(timeout=5000)
        assert bar.get_attribute("role") == "log"
        assert bar.get_attribute("aria-live") == "polite"

    def test_strip_has_button_role(self, page):
        delete_all_tasks()
        user_id = get_user_id(page)
        report_id = create_report(page)
        insert_task(user_id, report_id, status="running")

        navigate_to_dashboard(page)
        strip = page.locator(".task-bar__strip")
        expect(strip).to_be_visible(timeout=5000)
        assert strip.get_attribute("role") == "button"
        assert strip.get_attribute("aria-expanded") == "false"

    def test_keyboard_expand(self, page):
        delete_all_tasks()
        user_id = get_user_id(page)
        report_id = create_report(page)
        insert_task(user_id, report_id, status="running")

        navigate_to_dashboard(page)
        strip = page.locator(".task-bar__strip")
        expect(strip).to_be_visible(timeout=5000)

        strip.focus()
        page.keyboard.press("Enter")
        page.wait_for_timeout(500)

        expect(page.locator(".task-bar__list")).to_be_visible()
        assert strip.get_attribute("aria-expanded") == "true"

    def test_progress_bar_aria(self, page):
        delete_all_tasks()
        user_id = get_user_id(page)
        report_id = create_report(page)
        insert_task(user_id, report_id, status="running", current_step=2, total_steps=4)

        navigate_to_dashboard(page)
        expect(page.locator(".task-bar")).to_be_visible(timeout=5000)

        ensure_expanded(page)

        pbar = page.locator("[role='progressbar']").first
        expect(pbar).to_be_visible()
        assert pbar.get_attribute("aria-valuenow") == "2"
        assert pbar.get_attribute("aria-valuemax") == "4"


class TestMultipleTasks:
    """TaskBar handling of multiple concurrent tasks."""

    def test_multiple_tasks_shown(self, page):
        delete_all_tasks()
        user_id = get_user_id(page)
        report_id = create_report(page)
        insert_task(user_id, report_id, status="running", title="Generating: Task A", current_step=1)
        insert_task(user_id, report_id, status="running", title="Generating: Task B", current_step=3)

        navigate_to_dashboard(page)
        expect(page.locator(".task-bar")).to_be_visible(timeout=5000)

        ensure_expanded(page)

        rows = page.locator(".task-bar__row")
        assert rows.count() == 2

    def test_dismiss_one_keeps_others(self, page):
        delete_all_tasks()
        user_id = get_user_id(page)
        report_id = create_report(page)
        task_a = insert_task(user_id, report_id, status="running", title="Generating: Task A")
        insert_task(user_id, report_id, status="running", title="Generating: Task B")

        navigate_to_dashboard(page)
        expect(page.locator(".task-bar")).to_be_visible(timeout=5000)

        # Complete task A
        update_task(task_a, status="completed", current_step=4,
                    finished_at=datetime.utcnow().isoformat(),
                    result_json=json.dumps({"text": "done"}))
        page.wait_for_timeout(5000)

        ensure_expanded(page)

        # Task A is completed — has a dismiss button. Task B is running — has a cancel button.
        # Both rows have .task-bar__cancel-btn but we want to dismiss the completed one.
        rows = page.locator(".task-bar__row")
        assert rows.count() == 2

        # Find the row containing "Task A" and click its dismiss button
        for i in range(rows.count()):
            row = rows.nth(i)
            if "Task A" in (row.text_content() or ""):
                dismiss_btn = row.locator(".task-bar__cancel-btn")
                if dismiss_btn.count() > 0:
                    dismiss_btn.first.click()
                    break

        page.wait_for_timeout(1000)

        # Task B should still be visible
        remaining = page.locator(".task-bar__row")
        assert remaining.count() >= 1
        expect(page.locator(".task-bar")).to_contain_text("Task B")
