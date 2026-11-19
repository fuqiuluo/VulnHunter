"""Functional unit tests for the kvstore engine."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from kvstore import AccessDeniedError, Engine, KeyValidationError, Principal, WriteConflictError


class TestKVStoreBaseline(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.data_dir = Path(self._tmp.name) / "store"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_basic_crud_and_reopen(self) -> None:
        with Engine.open(self.data_dir) as eng:
            eng.put("/orgs/acme/projects/billing/secrets/api_key", b"sk-live-001")
            eng.put("/orgs/acme/projects/billing/config/region", "us-east-1")
            self.assertEqual(eng.get("/orgs/acme/projects/billing/secrets/api_key"), b"sk-live-001")

        with Engine.open(self.data_dir) as reopened:
            self.assertEqual(reopened.get("/orgs/acme/projects/billing/secrets/api_key"), b"sk-live-001")
            self.assertEqual(reopened.get("/orgs/acme/projects/billing/config/region"), b"us-east-1")

    def test_namespace_validation(self) -> None:
        with Engine.open(self.data_dir) as eng:
            for invalid in ("orgs/acme/k", "/orgs//acme/k", "/orgs/../k", "/orgs/acme/"):
                with self.assertRaises(KeyValidationError):
                    eng.put(invalid, b"val")

    def test_atomic_bootstrap_policy_and_secret_in_single_tx(self) -> None:
        alice = Principal.user("alice", roles=["billing-dev"])
        iam_admin = Principal.user("iam-admin")

        with Engine.open(self.data_dir) as eng:
            eng.grant_policy("iam-root", prefix="/orgs/acme", permissions=["grant"], subject="iam-admin")
            with eng.transaction(principal=iam_admin) as tx:
                tx.set_policy(
                    "billing-dev-rw",
                    prefix="/orgs/acme/projects/billing",
                    permissions=["read", "write", "list"],
                    role="billing-dev",
                )
                tx.put("/orgs/acme/projects/billing/secrets/db_url", b"postgres://db/billing", principal=alice)

            self.assertEqual(
                eng.get("/orgs/acme/projects/billing/secrets/db_url", principal=alice),
                b"postgres://db/billing",
            )
            with self.assertRaises(AccessDeniedError):
                eng.put("/orgs/acme/projects/other/secrets/s1", b"x", principal=alice)

    def test_nested_savepoints_on_kv_values(self) -> None:
        with Engine.open(self.data_dir) as eng:
            tx = eng.begin()
            tx.put("/orgs/acme/config/a", b"1")
            tx.savepoint("sp1")
            tx.put("/orgs/acme/config/b", b"2")
            tx.release_savepoint("sp1")
            tx.savepoint("sp2")
            tx.put("/orgs/acme/config/c", b"3")
            tx.put("/orgs/acme/config/b", b"overwritten")
            tx.rollback_to("sp2")
            tx.commit()

            self.assertEqual(eng.get("/orgs/acme/config/a"), b"1")
            self.assertEqual(eng.get("/orgs/acme/config/b"), b"2")
            self.assertIsNone(eng.get("/orgs/acme/config/c"))

    def test_snapshot_isolation_and_write_conflict(self) -> None:
        with Engine.open(self.data_dir) as eng:
            eng.put("/orgs/acme/config/version", b"v1")
            snap_before = eng.snapshot()

            tx1 = eng.begin()
            tx2 = eng.begin()
            tx1.put("/orgs/acme/config/version", b"v2")
            tx2.put("/orgs/acme/config/version", b"v3")
            tx1.commit()
            with self.assertRaises(WriteConflictError):
                tx2.commit()

            snap_after = eng.snapshot()
            self.assertEqual(snap_before.get("/orgs/acme/config/version"), b"v1")
            self.assertEqual(snap_after.get("/orgs/acme/config/version"), b"v2")
            snap_before.close()
            snap_after.close()

    def test_checkpoint_persists_live_entries(self) -> None:
        with Engine.open(self.data_dir) as eng:
            eng.put("/orgs/acme/secrets/k1", b"one")
            eng.put("/orgs/acme/secrets/k1", b"two")
            eng.put("/orgs/acme/secrets/k2", b"keep")
            stats = eng.checkpoint()
            self.assertGreaterEqual(stats["pruned_versions"], 1)

        with Engine.open(self.data_dir) as reopened:
            self.assertEqual(reopened.get("/orgs/acme/secrets/k1"), b"two")
            self.assertEqual(reopened.get("/orgs/acme/secrets/k2"), b"keep")


if __name__ == "__main__":
    unittest.main()
