import csv
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import backend


class Release129Tests(unittest.TestCase):
    def host(self, **overrides):
        return {"site": "New site", "ip": "192.0.2.1", "vlan": "", "cidr": "192.0.2.0/24",
                "direct_target": True, "hostname": "app01", "role": "Payments", "services": ["SSH"],
                "open_ports": [22], "os_family": "Linux", "os_version": "RHEL 9.6", "resources": {},
                **overrides}

    def test_direct_scope_without_vlan_and_deduplicated_addresses(self):
        plan = backend.build_address_plan({"scan_mode": "direct_only", "direct_target_group": "New site",
                  "direct_targets": [{"ip": "192.0.2.0/24"}, {"ip": "192.0.2.1"}]})
        self.assertEqual(len(plan), 254)
        self.assertTrue(all(h["site"] == "New site" and not h["vlan"] and h["direct_target"] for h in plan))
        for scope, count in [("192.0.2.0/31", 2), ("192.0.2.1/32", 1)]:
            self.assertEqual(len(backend.build_address_plan({"direct_targets": [{"cidr": scope}]})), count)
        for scope in ("192.0.2.0/19", "2001:db8::/120"):
            with self.assertRaises(ValueError):
                backend.build_address_plan({"direct_targets": [{"ip": scope}]})

    def test_progress_not_complete_during_enrichment_or_inventory(self):
        job = backend.ScanJob(id="qa", config={"direct_targets": [{"ip": "192.0.2.1"}], "ssh_resources": True})
        observations = []
        def observe(*_):
            observations.append((job.current_phase, job.public()["progress"]))
        with patch.object(backend, "scan_host", return_value=self.host()), \
             patch.object(backend, "enrich_ssh_resources", side_effect=observe), \
             patch.object(backend, "record_scan_inventory", side_effect=observe), \
             patch.object(backend, "save_job"):
            backend.run_scan(job)
        self.assertEqual(len(observations), 2)
        self.assertTrue(all(progress == 99 for _, progress in observations))
        self.assertEqual(job.public()["progress"], 100)
        job.status = "cancelled"
        self.assertEqual(job.public()["progress"], 99)

    def test_flags_and_direct_scope_site_override_survive_rescan(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(backend, "HOSTS_DB", Path(directory) / "hosts.db"):
            host = self.host()
            backend.remember_job_hosts(backend.ScanJob(id="qa", config={}, results=[host]))
            backend.flag_remembered_host({"site": host["site"], "ip": host["ip"], "flagged": True})
            backend.update_remembered_site(host["site"], host["ip"], "Assigned site")
            backend.remember_job_hosts(backend.ScanJob(id="again", config={}, results=[host]))
            stored = backend.list_remembered_hosts()
            self.assertEqual(len(stored), 1)
            self.assertEqual(stored[0]["site"], "Assigned site")
            self.assertTrue(stored[0]["deletion_candidate"])
            self.assertTrue(stored[0]["flagged_at"])
            backend.flag_remembered_host({"site": "Assigned site", "ip": host["ip"], "flagged": False})
            self.assertFalse(backend.list_remembered_hosts()[0]["deletion_candidate"])
            with self.assertRaises(ValueError):
                backend.flag_remembered_host({"site": "Assigned site", "ip": host["ip"], "flagged": "yes"})

    def test_role_names_flat_folders_and_unique_windows_keys(self):
        hosts = [self.host(os_family="Windows", system_id="id", system_name="RMS-Site-A"),
                 self.host(ip="192.0.2.2", role="Payments (2)", system_id="id", system_name="RMS-Site-A")]
        job = backend.ScanJob(id="export", config={}, results=hosts)
        output = backend.export_mobaxterm(job).decode("cp1252")
        self.assertIn("SubRep=RMS-Site-A\r\n", output)
        self.assertIn("Payments=#109#", output)
        self.assertIn("Payments (2)=#91#", output)
        self.assertIn("Payments (2) (2)=#109#", output)
        self.assertNotIn("app01=", output)
        self.assertNotIn(" - SSH=", output)
        self.assertNotIn(" - RDP=", output)
        self.assertNotIn("RMS-Site-A\\Windows", output)
        rows = list(csv.DictReader(io.StringIO(backend.export_csv(job).decode("utf-8-sig"))))
        self.assertEqual([r["role"] for r in rows], ["Payments", "Payments", "Payments (2)"])
        self.assertEqual([r["protocol"] for r in rows], ["SSH", "RDP", "SSH"])

    def test_128_database_migration_preserves_roles_and_systems(self):
        from contextlib import closing
        with tempfile.TemporaryDirectory() as directory, patch.object(backend, "HOSTS_DB", Path(directory) / "hosts.db"):
            backend.remember_job_hosts(backend.ScanJob(id="qa", config={}, results=[self.host()]))
            backend.update_remembered_role("New site", "192.0.2.1", "Custom role")
            system_id = backend.edit_system({"name": "Existing system"})["id"]
            backend.move_system_hosts({"system_id": system_id, "hosts": [{"site": "New site", "ip": "192.0.2.1"}]})
            with closing(backend.hosts_db_connection()) as connection, connection:
                for column in ("direct_target", "target_label", "deletion_candidate", "flagged_at"):
                    connection.execute(f"ALTER TABLE remembered_hosts DROP COLUMN {column}")
            backend.init_hosts_db()
            stored = backend.list_remembered_hosts()[0]
            self.assertEqual(stored["role"], "Custom role")
            self.assertEqual(stored["system_name"], "Existing system")
            self.assertFalse(stored["deletion_candidate"])
            self.assertEqual(stored["flagged_at"], "")


if __name__ == "__main__":
    unittest.main()
