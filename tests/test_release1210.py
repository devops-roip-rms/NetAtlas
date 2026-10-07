import csv
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import backend


class Release1210Tests(unittest.TestCase):
    def host(self, name, number=1, **extra):
        return {"site": "Test", "ip": f"192.0.2.{number}", "hostname": f"host{number}", "role": f"Role {number}",
                "vlan": "", "cidr": "192.0.2.0/24", "os_family": "Linux", "services": ["SSH"], "open_ports": [22],
                "resources": {}, "system_id": str(number), "system_name": name, **extra}

    def test_requested_tree_and_numeric_rafael_group(self):
        names = ["RMS-B", "RMS-NP-B", "RMS-A", "RMS-NP-A", "99-3", "88-1", "392-3", "874-3"]
        hosts = [self.host(name, i+1) for i, name in enumerate(names)]
        output = backend.export_mobaxterm(backend.ScanJob(id="tree", config={}, results=hosts)).decode("cp1252")
        for folder in ["RMS", "RMS\\RMS-A", "RMS\\RMS-B", "RMS\\NP", "RMS\\NP\\RMS-NP-A", "RMS\\NP\\RMS-NP-B", "RAFAEL"]:
            self.assertIn(f"SubRep={folder}\r\n", output)
        for name in names[4:]:
            self.assertIn(f"SubRep=RAFAEL\\{name}\r\n", output)
        self.assertLess(output.index("SubRep=RMS\\RMS-A\r\n"), output.index("SubRep=RMS\\RMS-B\r\n"))

    def test_non_numeric_and_single_system_names_not_overgrouped(self):
        names = ["99-3-extra", "Single-A", "RMS2", "RMS10"]
        for name in names:
            self.assertEqual(backend.system_folder(name, names), name)
        self.assertEqual(backend.system_folder("", names), "Unassigned")
        mixed = ["RMS-A", "rms-B", "RMS-NP-A", "rms-np-B"]
        paths = [backend.system_folder(name, mixed) for name in mixed]
        self.assertEqual(len({path.split("\\")[0] for path in paths}), 1)
        self.assertEqual(paths[2].split("\\")[:2], paths[3].split("\\")[:2])

    def test_system_catalog_sorting_and_selected_exports_stay_grouped(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(backend, "HOSTS_DB", Path(directory) / "hosts.db"):
            names = ["Zulu", "RMS-NP-B", "RMS-10", "RMS-NP-A", "RMS-2", "alpha"]
            for index, name in enumerate(names, 1):
                system = backend.edit_system({"name": name})["id"]
                host = self.host(name, index)
                backend.remember_job_hosts(backend.ScanJob(id="seed", config={}, results=[host]))
                backend.move_system_hosts({"system_id": system, "hosts": [{"site": "Test", "ip": host["ip"]}]})
            self.assertEqual([s["name"] for s in backend.list_systems()], ["alpha", "RMS-2", "RMS-10", "RMS-NP-A", "RMS-NP-B", "Zulu"])
            stored = backend.list_remembered_hosts()
            selected = [h for h in stored if h["system_name"] == "RMS-NP-A"]
            job = backend.ScanJob(id="selected", config={}, results=selected)
            self.assertIn("SubRep=RMS\\NP\\RMS-NP-A\r\n", backend.export_mobaxterm(job).decode("cp1252"))
            csv_row = list(csv.DictReader(io.StringIO(backend.export_csv(job).decode("utf-8-sig"))))[0]
            self.assertEqual(csv_row["system"], "RMS-NP-A")
            self.assertEqual(csv_row["folder"], "NetAtlas\\RMS\\NP\\RMS-NP-A")
            inventory_row = list(csv.DictReader(io.StringIO(backend.export_inventory_csv(job).decode("utf-8-sig"))))[0]
            self.assertEqual(inventory_row["system"], "RMS-NP-A")

    def test_exports_sort_by_system_name_keep_manual_host_order(self):
        hosts = [self.host("Zulu", 1, system_order=0), self.host("RMS-10", 2, system_order=1),
                 self.host("RMS-2", 3, system_order=4, system_position=1),
                 self.host("RMS-2", 4, system_order=4, system_position=0)]
        self.assertEqual([h["ip"] for h in backend.ordered_export_hosts(hosts)], ["192.0.2.4", "192.0.2.3", "192.0.2.2", "192.0.2.1"])
        unassigned = self.host("", 1)
        row = list(csv.DictReader(io.StringIO(backend.export_csv(backend.ScanJob(id="x", config={}, results=[unassigned])).decode("utf-8-sig"))))[0]
        self.assertEqual(row["system"], "Unassigned")


if __name__ == "__main__":
    unittest.main()
