import copy
from contextlib import closing
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import backend


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.db_patch = patch.object(backend, "HOSTS_DB", self.directory / "hosts.db")
        self.data_patch = patch.object(backend, "DATA_DIR", self.directory)
        self.db_patch.start(); self.data_patch.start()
        self.addCleanup(self.db_patch.stop); self.addCleanup(self.data_patch.stop)
        backend.init_hosts_db()
        self.old_schedule = copy.deepcopy(backend.SCHEDULE)
        self.old_secrets = dict(backend.SCHEDULE_SECRETS)
        self.old_jobs = dict(backend.JOBS)
        self.addCleanup(self.restore_globals)
        backend.JOBS.clear()
        backend.SCHEDULE.update(enabled=False, interval_minutes=60, config={}, next_run=None, active_job=None, last_run=None, error="")
        backend.SCHEDULE_SECRETS.clear()

    def restore_globals(self):
        backend.SCHEDULE.clear(); backend.SCHEDULE.update(self.old_schedule)
        backend.SCHEDULE_SECRETS.clear(); backend.SCHEDULE_SECRETS.update(self.old_secrets)
        backend.JOBS.clear(); backend.JOBS.update(self.old_jobs)

    def host(self, ip="192.0.2.1", site="Site A", **extra):
        return {"ip": ip, "site": site, "vlan": "VLAN 95", "cidr": "192.0.2.0/24", "hostname": "app-" + ip.split(".")[-1],
                "services": ["SSH"], "open_ports": [22], "os_family": "Linux", "os_version": "RHEL 9.6", "os_confidence": 100,
                "resources": {"cpu_cores": "4", "ram_gb": "16"}, "discovered_at": "2026-01-01T00:00:00+00:00", **extra}

    def remember(self, hosts):
        backend.remember_job_hosts(backend.ScanJob(id="manual", config={}, results=hosts))

    def test_overview_uses_inventory_and_actual_addition_date(self):
        self.remember([self.host()])
        backend.JOBS["other"] = backend.ScanJob(id="other", config={}, results=[self.host("192.0.2.2", os_family="Windows")])
        result = backend.remembered_overview()
        self.assertEqual(result["summary"]["hosts"], 1)
        self.assertEqual(result["summary"]["linux"], 1)
        self.assertEqual(result["summary"]["reachable"], 1)
        self.assertNotEqual(result["latest_added"][0]["added_at"], "2026-01-01T00:00:00+00:00")
        self.assertEqual(result["breakdown"]["sites"][0]["ram_gb"], 16)

    def test_reachability_is_scoped_to_site_and_checked_addresses(self):
        hosts = [self.host(), self.host(site="Site B"), self.host("192.0.2.2")]
        self.remember(hosts)
        job = backend.ScanJob(id="offline", config={}, total=1, completed=1, results=[])
        backend.record_scan_inventory(job, [hosts[0]])
        overview = backend.remembered_overview()
        self.assertEqual(overview["summary"]["reachable"], 2)
        self.assertEqual(overview["summary"]["unreachable"], 1)
        self.assertEqual(overview["summary"]["hosts"], 3)
        failed = backend.ScanJob(id="errors", config={}, completed=1, errors=["network failed"])
        backend.record_scan_inventory(failed, [hosts[1]])
        self.assertEqual(backend.remembered_overview()["summary"]["unreachable"], 1)

    def test_background_new_hosts_deduplicate_and_require_approval(self):
        known, new = self.host(), self.host("192.0.2.2")
        self.remember([known])
        job = backend.ScanJob(id="bg", config={"background_scan": True}, completed=2, results=[known, new, self.host("192.0.2.3", hostname="")])
        backend.record_scan_inventory(job, [known, new])
        backend.record_scan_inventory(job, [known, new])
        self.assertEqual(len(backend.list_remembered_hosts()), 1)
        self.assertEqual(len(backend.list_discoveries()), 1)
        backend.review_discoveries({"action": "approve", "hosts": [{"site": new["site"], "ip": new["ip"]}]})
        self.assertEqual(len(backend.list_remembered_hosts()), 2)
        self.assertEqual(backend.list_discoveries(), [])
        backend.record_scan_inventory(job, [known, new])
        self.assertEqual(backend.list_discoveries(), [])

    def test_dismissed_hosts_do_not_return_and_manual_scan_can_add_them(self):
        host = self.host()
        job = backend.ScanJob(id="bg", config={"background_scan": True}, completed=1, results=[host])
        backend.record_scan_inventory(job, [host])
        backend.review_discoveries({"action": "dismiss", "hosts": [{"site": host["site"], "ip": host["ip"]}]})
        backend.record_scan_inventory(job, [host])
        self.assertEqual(backend.list_discoveries(), [])
        self.remember([host])
        self.assertEqual(len(backend.list_remembered_hosts()), 1)

    def test_system_order_and_multi_host_move_survive_rescan_and_site_change(self):
        hosts = [self.host(f"192.0.2.{index}", cidr=f"192.0.2.{index}/32") for index in range(1, 4)]
        self.remember(hosts)
        first = backend.edit_system({"name": "RMS-Site-A"})["id"]
        second = backend.edit_system({"name": "RMS-Site-B"})["id"]
        backend.move_system_hosts({"system_id": first, "hosts": [{"site": h["site"], "ip": h["ip"]} for h in hosts]})
        backend.move_system_hosts({"system_id": first, "position": 0, "hosts": [{"site": hosts[2]["site"], "ip": hosts[2]["ip"]}]})
        backend.edit_system({"action": "reorder", "ids": [second, first]})
        backend.update_remembered_site("Site A", hosts[2]["ip"], "Moved Site")
        self.remember(hosts)
        stored = backend.list_remembered_hosts()
        ordered = backend.ordered_export_hosts(stored)
        self.assertEqual([h["ip"] for h in ordered], [hosts[2]["ip"], hosts[0]["ip"], hosts[1]["ip"]])
        self.assertEqual(ordered[0]["site"], "Moved Site")
        job = backend.ScanJob(id="export", config={}, results=stored)
        text = backend.export_mobaxterm(job).decode("cp1252")
        self.assertIn("SubRep=RMS\\Site\\RMS-Site-A\r\n", text)
        self.assertLess(text.index("app-3="), text.index("app-1="))
        self.assertIn("NetAtlas\\RMS\\Site\\RMS-Site-A", backend.export_csv(job).decode("utf-8-sig"))
        backend.edit_system({"action": "delete", "id": first})
        self.assertEqual(len(backend.list_remembered_hosts()), 3)
        self.assertTrue(all(not host["system_id"] for host in backend.list_remembered_hosts()))

    def test_background_preserves_auth_resources_and_known_hostname_on_dns_failure(self):
        host = self.host()
        self.remember([host])
        observed = self.host(hostname="", resources={}, os_version="", os_family="Unknown", os_confidence=0)
        job = backend.ScanJob(id="bg", config={"background_scan": True}, completed=1, results=[observed])
        backend.record_scan_inventory(job, [host])
        stored = backend.list_remembered_hosts()[0]
        self.assertEqual(stored["hostname"], host["hostname"])
        self.assertEqual(stored["resources"]["ram_gb"], "16")
        self.assertEqual(stored["os_version"], "RHEL 9.6")
        lower_confidence = self.host(os_family="Windows", os_version="Windows fingerprint", os_confidence=82, resources={})
        self.remember([lower_confidence])
        stored = backend.list_remembered_hosts()[0]
        self.assertEqual(stored["os_family"], "Linux")
        self.assertEqual(stored["os_version"], "RHEL 9.6")

    def test_schedule_credentials_are_encrypted_and_resume_after_restart(self):
        config = {"sites": [{"name": "Test", "vlans": [{"name": "Test", "cidr": "192.0.2.1/32"}]}],
                  "ssh_resources": True, "linux_ssh_username": "ops", "linux_ssh_password": "unique-secret-password"}
        public = backend.configure_schedule({"interval_minutes": 5, "config": config})
        self.assertNotIn("unique-secret-password", json.dumps(public))
        with closing(backend.hosts_db_connection()) as connection:
            stored = connection.execute("SELECT value FROM settings").fetchone()[0]
        self.assertNotIn("unique-secret-password", stored)
        backend.SCHEDULE_SECRETS.clear(); backend.SCHEDULE["enabled"] = False
        backend.load_schedule()
        self.assertTrue(backend.SCHEDULE["enabled"])
        self.assertEqual(backend.SCHEDULE_SECRETS["linux_ssh_password"], "unique-secret-password")
        backend.configure_schedule({"action": "stop"})
        backend.SCHEDULE_SECRETS["bad"] = "old"
        backend.SCHEDULE_SECRETS.clear(); backend.load_schedule()
        self.assertFalse(backend.SCHEDULE["enabled"])
        self.assertEqual(backend.SCHEDULE_SECRETS, {})

    def test_scheduler_prevents_overlap_and_waits_interval_after_completion(self):
        backend.configure_schedule({"interval_minutes": 5, "config": {"direct_targets": [{"ip": "192.0.2.1"}]}})
        backend.JOBS["manual"] = backend.ScanJob(id="manual", config={})
        with patch.object(backend.threading, "Thread") as thread:
            backend.scheduler_tick()
            thread.assert_not_called()
            backend.JOBS["manual"].status = "complete"
            backend.scheduler_tick()
            thread.assert_called_once()
        active = backend.JOBS[backend.SCHEDULE["active_job"]]
        self.assertTrue(active.config["background_scan"])
        active.status = "complete"; active.finished_at = backend.utc_now()
        with patch.object(backend.time, "time", return_value=1000), patch.object(backend.threading, "Thread") as thread:
            backend.scheduler_tick()
            self.assertEqual(backend.SCHEDULE["next_run"], 1300)
            thread.assert_not_called()

    def test_existing_127_database_migrates_without_losing_inventory(self):
        self.remember([self.host()])
        with closing(backend.hosts_db_connection()) as connection, connection:
            for column in ("system_id", "system_position", "reachable", "last_checked", "added_at"):
                connection.execute(f"ALTER TABLE remembered_hosts DROP COLUMN {column}")
        backend.init_hosts_db()
        host = backend.list_remembered_hosts()[0]
        self.assertEqual(host["hostname"], "app-1")
        self.assertIsNone(host["reachable"])
        self.assertEqual(host["added_at"], host["first_seen"])
        self.assertEqual(backend.remembered_overview()["summary"]["unchecked"], 1)

    def test_schedule_persistence_error_does_not_enable_unsaved_scans(self):
        with patch.object(backend, "save_schedule", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                backend.configure_schedule({"config": {"direct_targets": [{"ip": "192.0.2.1"}]}})
        self.assertFalse(backend.SCHEDULE["enabled"])
        self.assertEqual(backend.SCHEDULE_SECRETS, {})


if __name__ == "__main__":
    unittest.main()
