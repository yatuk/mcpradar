"""Watcher tests — mock-based coverage."""

from __future__ import annotations


class TestWatcherStoreReuse:
    def test_store_opened_once(self) -> None:
        from mcpradar.watch.watcher import Watcher

        w = Watcher(target="http://x", transport="http", interval=999)
        assert w._store is not None
        assert w.interval == 999
        assert w.alert_cmd is None
        assert w.alert_webhook is None
        w._store.close()

    def test_webhook_and_cmd_set(self) -> None:
        from mcpradar.watch.watcher import Watcher

        w = Watcher(
            target="http://x",
            alert_cmd="echo hi",
            alert_webhook="https://hooks.slack.com/x",
        )
        assert w.alert_cmd == "echo hi"
        assert w.alert_webhook == "https://hooks.slack.com/x"
        w._store.close()


class TestWatcherRunHelper:
    def test_run_alert_no_cmd_returns_early(self) -> None:
        from mcpradar.watch.watcher import Watcher

        w = Watcher(target="http://x")
        w._store.close()
        w._run_alert(None)

    def test_run_webhook_no_url_returns_early(self) -> None:
        from mcpradar.watch.watcher import Watcher

        w = Watcher(target="http://x")
        w._store.close()
        w._run_webhook(None)

    def test_run_alert_with_cmd(self) -> None:
        from mcpradar.watch.watcher import Watcher

        w = Watcher(target="http://x", alert_cmd="echo hello")
        w._store.close()
        w._run_alert({"test": True})

    def test_run_alert_with_none_cmd_after_set(self) -> None:
        from mcpradar.watch.watcher import Watcher

        # Force alert_cmd to become None before _run_alert
        w = Watcher(target="http://x", alert_cmd="")
        w._store.close()
        w._run_alert({})

    def test_last_report_initial_none(self) -> None:
        from mcpradar.watch.watcher import Watcher

        w = Watcher(target="http://x")
        assert w.last_report is None
        w._store.close()
