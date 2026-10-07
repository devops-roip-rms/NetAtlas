import configparser
from contextlib import closing
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import backend


class Release1211Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = patch.object(backend, "HOSTS_DB", Path(self.temp.name)/"hosts.db")
        self.db.start(); self.addCleanup(self.db.stop)
        backend.init_hosts_db()

    def host(self, octet, hostname="server", site="Site A", **extra):
        return {"site":site,"ip":f"192.0.2.{octet}","hostname":hostname,"vlan":"95","cidr":"192.0.2.0/24",
                "os_family":"Linux","os_version":"RHEL 9.6","os_confidence":100,"services":["SSH"],"open_ports":[22],"resources":{"ram_gb":"16"}, **extra}

    def remember(self, hosts):
        backend.remember_job_hosts(backend.ScanJob(id="test",config={},results=hosts))

    def test_nonzero_ending_address_wins_in_both_discovery_orders(self):
        for index,(bad,good) in enumerate([(10,13),(50,52),(100,107)]):
            name=f"host{index}"
            self.remember([self.host(bad,name),self.host(good,name.upper()+".tng.topsecret")])
            self.remember([self.host(good,name),self.host(bad,name)])
        stored=backend.list_remembered_hosts()
        self.assertEqual({h["ip"] for h in stored},{"192.0.2.13","192.0.2.52","192.0.2.107"})

    def test_replacement_preserves_manual_state_and_archives_duplicate(self):
        self.remember([self.host(10)])
        backend.update_remembered_role("Site A","192.0.2.10","Payments")
        system=backend.edit_system({"name":"RMS-A"})["id"]
        backend.move_system_hosts({"system_id":system,"hosts":[{"site":"Site A","ip":"192.0.2.10"}]})
        backend.flag_remembered_host({"site":"Site A","ip":"192.0.2.10","flagged":True})
        self.remember([self.host(13,resources={},os_version="",os_confidence=0)])
        host=backend.list_remembered_hosts()[0]
        self.assertEqual(host["ip"],"192.0.2.13")
        self.assertEqual(host["role"],"Payments")
        self.assertEqual(host["system_id"],system)
        self.assertTrue(host["deletion_candidate"])
        self.assertEqual(host["resources"]["ram_gb"],"16")
        self.assertEqual(host["os_version"],"RHEL 9.6")
        with closing(backend.hosts_db_connection()) as db:
            archive=db.execute("SELECT * FROM duplicate_host_archive").fetchone()
        self.assertEqual(archive["survivor_ip"],"192.0.2.13")
        self.assertEqual(json.loads(archive["record_json"])["role"],"Payments")

    def test_site_boundaries_distinct_names_and_stable_ties(self):
        self.remember([self.host(13),self.host(10,site="Site B"),self.host(20,"different")])
        self.remember([self.host(17)])
        self.assertEqual({(h["site"],h["ip"]) for h in backend.list_remembered_hosts()},
                         {("Site A","192.0.2.13"),("Site B","192.0.2.10"),("Site A","192.0.2.20")})
        self.remember([self.host(30,"onlyzero"),self.host(40,"onlyzero")])
        self.assertEqual(len(backend.list_remembered_hosts()),4)

    def test_background_known_alias_updates_and_new_alias_queue_approval(self):
        self.remember([self.host(10)])
        hosts=[self.host(13),self.host(50,"newserver"),self.host(52,"newserver")]
        job=backend.ScanJob(id="bg",config={"background_scan":True},completed=3,results=hosts)
        backend.record_scan_inventory(job,hosts)
        self.assertEqual([h["ip"] for h in backend.list_remembered_hosts()],["192.0.2.13"])
        self.assertEqual([h["ip"] for h in backend.list_discoveries()],["192.0.2.52"])
        backend.review_discoveries({"action":"approve","hosts":[{"site":"Site A","ip":"192.0.2.52"}]})
        self.assertEqual(len(backend.list_remembered_hosts()),2)
        self.assertEqual(backend.list_discoveries(),[])

    def test_bulk_delete_validates_entire_selection_and_is_atomic(self):
        self.remember([self.host(1,"one"),self.host(2,"two"),self.host(3,"three")])
        with self.assertRaises(ValueError):
            backend.delete_remembered_selected({"hosts":[{"site":"Site A","ip":"192.0.2.1"},{"site":"Site A","ip":"192.0.2.99"}]})
        self.assertEqual(len(backend.list_remembered_hosts()),3)
        result=backend.delete_remembered_selected({"hosts":[{"site":"Site A","ip":"192.0.2.1"},{"site":"Site A","ip":"192.0.2.2"}]})
        self.assertEqual(result["count"],2)
        self.assertEqual([h["ip"] for h in backend.list_remembered_hosts()],["192.0.2.3"])
        with self.assertRaises(ValueError): backend.delete_remembered_selected({"hosts":[]})

    def test_dismissed_identity_stays_hidden_on_a_new_address(self):
        host=self.host(50,"pending")
        backend.record_scan_inventory(backend.ScanJob(id="bg",config={"background_scan":True},results=[host]),[host])
        backend.review_discoveries({"action":"dismiss","hosts":[{"site":"Site A","ip":host["ip"]}]})
        alias=self.host(52,"PENDING")
        backend.record_scan_inventory(backend.ScanJob(id="next",config={"background_scan":True},results=[alias]),[alias])
        self.assertEqual(backend.list_discoveries(),[])

    def test_bulk_delete_rolls_back_if_any_database_delete_fails(self):
        import sqlite3
        self.remember([self.host(1,"one"),self.host(2,"two")])
        with closing(backend.hosts_db_connection()) as db, db:
            db.execute("CREATE TRIGGER reject_second BEFORE DELETE ON remembered_hosts WHEN old.ip='192.0.2.2' BEGIN SELECT RAISE(ABORT,'simulated failure'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            backend.delete_remembered_selected({"hosts":[{"site":"Site A","ip":"192.0.2.1"},{"site":"Site A","ip":"192.0.2.2"}]})
        self.assertEqual(len(backend.list_remembered_hosts()),2)

    def test_system_reordering_and_export_icon_inheritance(self):
        ids=[backend.edit_system({"name":name})["id"] for name in ["RMS-A","RMS-NP-A","RMS-NP-B","99-3"]]
        backend.edit_system({"action":"reorder","ids":list(reversed(ids))})
        self.assertEqual([s["id"] for s in backend.list_systems()],list(reversed(ids)))
        hosts=[]
        for i,system in enumerate(backend.list_systems(),1):
            hosts.append(self.host(i,f"host{i}",system_id=system["id"],system_name=system["name"],system_order=i))
        with patch.object(backend.random,"choice",side_effect=[109,91]) as choose:
            output=backend.export_mobaxterm(backend.ScanJob(id="export",config={},results=hosts)).decode("cp1252")
            self.assertEqual(choose.call_count,2)
        ini=configparser.ConfigParser(interpolation=None,strict=True); ini.read_string(output)
        roots={}
        for section in ini.sections()[1:]:
            root=ini[section]["SubRep"].split("\\")[0]
            icon=ini[section]["ImgNum"]
            self.assertEqual(icon,roots.setdefault(root,icon))
        self.assertEqual(roots,{"RAFAEL":"109","RMS":"91"})


if __name__ == "__main__": unittest.main()
