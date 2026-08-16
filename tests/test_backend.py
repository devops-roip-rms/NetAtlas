import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import backend


class NetAtlasTests(unittest.TestCase):
    def test_address_plan(self):
        plan = backend.build_address_plan({"sites": [{"name": "HQ", "vlans": [{"name": "Users", "cidr": "192.0.2.0/30"}]}]})
        self.assertEqual([x["ip"] for x in plan], ["192.0.2.1", "192.0.2.2"])

    def test_os_inference(self):
        family, version, confidence, _ = backend.infer_os([22], "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3", [])
        self.assertEqual(family, "Linux")
        self.assertIn("Ubuntu", version)
        self.assertGreater(confidence, 80)

    def test_windows_openssh_inference(self):
        family, version, confidence, _ = backend.infer_os([22], "SSH-2.0-OpenSSH_for_Windows_9.5", [])
        self.assertEqual(family, "Windows")
        self.assertIn("Windows", version)
        self.assertGreaterEqual(confidence, 90)

    def test_mobaxterm_export(self):
        host = {"site": "HQ", "vlan": "Servers", "ip": "192.0.2.10", "hostname": "app01", "services": ["SSH", "HTTPS"], "open_ports": [22, 443], "web": [{"url": "https://192.0.2.10"}], "os_family": "Linux", "os_version": "Ubuntu 24.04"}
        job = backend.ScanJob(id="demo", config={}, results=[host], status="complete")
        text = backend.export_mobaxterm(job, "ops").decode("cp1252")
        self.assertIn("[Bookmarks_1]", text)
        self.assertIn("SubRep=Linux\\HQ\\Servers", text)
        self.assertIn("app01 - SSH=#109#0%192.0.2.10%22%ops", text)
        self.assertNotIn("HTTPS", text)
        self.assertNotIn("#313#", text)

    def test_windows_dual_protocol_export(self):
        host = {"site": "Branch", "vlan": "Servers", "ip": "192.0.2.20", "hostname": "win01", "services": ["RDP"], "open_ports": [3389], "web": [], "os_family": "Windows", "os_version": "Windows Server 2022"}
        job = backend.ScanJob(id="windows", config={}, results=[host], status="complete")
        text = backend.export_mobaxterm(job, "ops", "DOMAIN\\ops").decode("cp1252")
        self.assertIn("SubRep=Windows\\Branch\\Servers", text)
        self.assertIn("win01 - SSH=#109#0%192.0.2.20%22%ops", text)
        self.assertIn("win01 - RDP=#91#4%192.0.2.20%3389%DOMAIN\\ops", text)

    def test_windows_build_mapping(self):
        self.assertEqual(backend.windows_version_from_build("10.0.20348"), "Windows Server 2022 (build 10.0.20348)")
        self.assertEqual(backend.windows_version_from_build("10.0.17763"), "Windows Server 2019 (build 10.0.17763)")

    def test_secrets_never_enter_public_job(self):
        job = backend.ScanJob(id="secret", config={"linux_ssh_username": "linuxops", "linux_ssh_password": "legacy-secret"}, secrets={"windows_ssh_password": "do-not-save"})
        public = job.public()
        self.assertNotIn("secrets", public)
        self.assertNotIn("do-not-save", str(public))
        self.assertNotIn("legacy-secret", str(public))

    def test_distinct_linux_and_windows_export_usernames(self):
        linux = {"site": "HQ", "vlan": "Servers", "ip": "192.0.2.40", "hostname": "rhel01", "services": ["SSH"], "open_ports": [22], "web": [], "os_family": "Linux", "os_version": "RHEL 9.6"}
        windows = {"site": "HQ", "vlan": "Servers", "ip": "192.0.2.41", "hostname": "win01", "services": ["RDP"], "open_ports": [3389], "web": [], "os_family": "Windows", "os_version": "Windows Server 2022"}
        job = backend.ScanJob(id="profiles", config={}, results=[linux, windows], status="complete")
        text = backend.export_mobaxterm(job, "linuxops", "DOMAIN\\rdpops", "DOMAIN\\winops").decode("cp1252")
        self.assertIn("rhel01 - SSH=#109#0%192.0.2.40%22%linuxops", text)
        self.assertIn("win01 - SSH=#109#0%192.0.2.41%22%DOMAIN\\winops", text)
        self.assertIn("win01 - RDP=#91#4%192.0.2.41%3389%DOMAIN\\rdpops", text)

    def test_windows_profile_is_tried_first_for_windows(self):
        host = {"ip": "192.0.2.50", "open_ports": [22], "os_family": "Windows", "ssh_banner": ""}
        calls = []
        def fake_try(_host, username, _password, profile):
            calls.append((profile, username))
            return True, ""
        with patch.object(backend, "try_ssh_profile", side_effect=fake_try):
            backend.enrich_ssh_resources(host, "linuxops", "linuxpass", "winops", "winpass")
        self.assertEqual(calls, [("Windows", "winops")])

    def test_unknown_host_falls_back_to_windows_profile(self):
        host = {"ip": "192.0.2.51", "open_ports": [22], "os_family": "Unknown", "ssh_banner": ""}
        calls = []
        def fake_try(_host, username, _password, profile):
            calls.append((profile, username))
            return profile == "Windows", "authentication failed"
        with patch.object(backend, "try_ssh_profile", side_effect=fake_try):
            backend.enrich_ssh_resources(host, "linuxops", "linuxpass", "winops", "winpass")
        self.assertEqual(calls, [("Linux", "linuxops"), ("Windows", "winops")])

    def test_inventory_csv_contains_hostname_and_resources(self):
        host = {"site": "HQ", "vlan": "Linux", "cidr": "192.0.2.0/24", "ip": "192.0.2.30", "hostname": "rhel96.example", "hostname_source": "Authenticated SSH", "services": ["SSH", "HTTPS"], "open_ports": [22, 443], "web": [{"url": "https://192.0.2.30"}], "os_family": "Linux", "os_version": "Red Hat Enterprise Linux 9.6 (Plow)", "os_confidence": 100, "os_evidence": "Authenticated /etc/os-release", "resource_status": "Collected via password-authenticated SSH", "resources": {"cpu_cores": "8", "ram_gb": "31.2", "disk_root_gb": "80.0/100.0"}}
        job = backend.ScanJob(id="inventory", config={}, results=[host], status="complete")
        text = backend.export_inventory_csv(job).decode("utf-8-sig")
        self.assertIn("rhel96.example", text)
        self.assertIn("Red Hat Enterprise Linux 9.6", text)
        self.assertIn("31.2", text)


if __name__ == "__main__":
    unittest.main()
