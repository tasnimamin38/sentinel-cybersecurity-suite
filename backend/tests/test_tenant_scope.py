import unittest

from sqlalchemy import create_engine, delete, insert, select, update
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import Asset, Tenant
from app.tenant_scope import TenantScopeViolation


LEGACY_TENANT_ID = "00000000-0000-4000-8000-000000000001"
TENANT_A = "00000000-0000-4000-8000-00000000000a"
TENANT_B = "00000000-0000-4000-8000-00000000000b"


def make_asset(asset_id: str, tenant_id: str, hostname: str, name: str) -> Asset:
    from datetime import UTC, datetime, timedelta

    return Asset(
        id=asset_id,
        tenant_id=tenant_id,
        hostname=hostname,
        name=name,
        owner="Security",
        environment="production",
        criticality=1.0,
        authorization_expires_at=datetime.now(UTC) + timedelta(days=30),
        authorization_reference="approved-test-scope",
        status="active",
        tags=[],
    )


class TenantScopedSessionTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite://")
        Base.metadata.create_all(self.engine)
        self.UnscopedSession = sessionmaker(bind=self.engine, expire_on_commit=False)
        self.ScopedSessionA = sessionmaker(
            bind=self.engine,
            expire_on_commit=False,
            info={"tenant_id": TENANT_A, "tenant_isolation_required": True},
        )
        self.ScopedSessionB = sessionmaker(
            bind=self.engine,
            expire_on_commit=False,
            info={"tenant_id": TENANT_B, "tenant_isolation_required": True},
        )
        with self.UnscopedSession() as db:
            db.add_all(
                [
                    Tenant(
                        id=LEGACY_TENANT_ID,
                        slug="legacy-installation",
                        name="Legacy Installation",
                        workspace_type="legacy",
                        status="active",
                    ),
                    Tenant(
                        id=TENANT_A,
                        slug="company-a",
                        name="Company A",
                        workspace_type="company",
                        status="active",
                    ),
                    Tenant(
                        id=TENANT_B,
                        slug="company-b",
                        name="Company B",
                        workspace_type="company",
                        status="active",
                    ),
                ]
            )
            db.add_all(
                [
                    make_asset("asset-a", TENANT_A, "app.example.com", "Company A asset"),
                    make_asset("asset-b", TENANT_B, "app.example.com", "Company B asset"),
                ]
            )
            db.commit()

    def tearDown(self):
        Base.metadata.drop_all(self.engine)
        self.engine.dispose()

    def test_select_and_get_never_return_another_tenants_asset(self):
        with self.ScopedSessionA() as db:
            rows = db.scalars(select(Asset).order_by(Asset.id)).all()
            self.assertEqual([row.id for row in rows], ["asset-a"])
            self.assertIsNone(db.get(Asset, "asset-b"))

        with self.ScopedSessionB() as db:
            self.assertIsNone(db.get(Asset, "asset-a"))
            self.assertEqual(db.get(Asset, "asset-b").name, "Company B asset")

    def test_orm_bulk_update_is_limited_to_the_active_tenant(self):
        with self.ScopedSessionA() as db:
            result = db.execute(update(Asset).values(name="Changed by A"))
            self.assertEqual(result.rowcount, 1)
            db.commit()

        with self.UnscopedSession() as db:
            self.assertEqual(db.get(Asset, "asset-a").name, "Changed by A")
            self.assertEqual(db.get(Asset, "asset-b").name, "Company B asset")

    def test_orm_bulk_delete_is_limited_to_the_active_tenant(self):
        with self.ScopedSessionA() as db:
            result = db.execute(delete(Asset))
            self.assertEqual(result.rowcount, 1)
            db.commit()

        with self.UnscopedSession() as db:
            self.assertIsNone(db.get(Asset, "asset-a"))
            self.assertIsNotNone(db.get(Asset, "asset-b"))

    def test_new_rows_inherit_the_session_tenant_without_client_input(self):
        from datetime import UTC, datetime, timedelta

        with self.ScopedSessionA() as db:
            item = Asset(
                id="asset-a-new",
                hostname="new.example.com",
                name="New tenant asset",
                owner="Security",
                environment="production",
                criticality=1.0,
                authorization_expires_at=datetime.now(UTC) + timedelta(days=30),
                authorization_reference="approved-test-scope",
                status="active",
                tags=[],
            )
            db.add(item)
            db.flush()
            self.assertEqual(item.tenant_id, TENANT_A)
            db.commit()

        with self.ScopedSessionB() as db:
            self.assertIsNone(db.get(Asset, "asset-a-new"))

    def test_bulk_update_cannot_reassign_a_row_to_another_tenant(self):
        with self.ScopedSessionA() as db:
            with self.assertRaises(TenantScopeViolation):
                db.execute(
                    update(Asset)
                    .where(Asset.id == "asset-a")
                    .values(tenant_id=TENANT_B)
                )

    def test_bulk_orm_insert_is_rejected_in_a_tenant_scoped_session(self):
        with self.ScopedSessionA() as db:
            with self.assertRaises(TenantScopeViolation):
                db.execute(
                    insert(Asset).values(
                        id="asset-bulk",
                        tenant_id=TENANT_B,
                        hostname="bulk.example.com",
                        name="Bulk insert",
                        owner="Security",
                        environment="production",
                        criticality=1.0,
                        authorization_expires_at="2030-01-01",
                        authorization_reference="approved",
                        status="active",
                        tags="[]",
                    )
                )

    def test_session_cannot_insert_or_mutate_another_tenants_object(self):
        with self.ScopedSessionA() as db:
            foreign = make_asset(
                "asset-forged",
                TENANT_B,
                "forged.example.com",
                "Forged tenant assignment",
            )
            db.add(foreign)
            with self.assertRaises(TenantScopeViolation):
                db.flush()
            db.rollback()

        with self.ScopedSessionA() as db:
            foreign = db.scalar(
                select(Asset)
                .where(Asset.id == "asset-b")
                .execution_options(skip_tenant_scope=True)
            )
            self.assertIsNotNone(foreign)
            foreign.name = "Attempted cross-tenant edit"
            with self.assertRaises(TenantScopeViolation):
                db.flush()
            db.rollback()

        with self.UnscopedSession() as db:
            self.assertEqual(db.get(Asset, "asset-b").name, "Company B asset")


if __name__ == "__main__":
    unittest.main()
