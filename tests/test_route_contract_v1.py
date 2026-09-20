from __future__ import annotations

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class RouteContractTests(unittest.TestCase):
    def test_authority_split_is_fail_closed(self):
        node = json.loads((ROOT / "config/route-contract.json").read_text())
        self.assertEqual(node["schema"], "mmibkr.public_runtime_route_contract.v4")
        self.assertEqual(node["runtime_repository"], "XoticHaze/mm-ibkr-runtime")
        self.assertEqual(node["private_authority_repository"], "XoticHaze/mm-IBKR")
        self.assertEqual(
            node["broker_compute_repository"],
            "XoticHaze/research-compute-public-",
        )
        self.assertEqual(node["canonical_b1_ref"], "ibkr-b1-authority-v1")
        self.assertFalse(node["live_trading_allowed"])
        self.assertFalse(node["direct_ibkr_credentials_allowed"])
        self.assertFalse(node["runtime_private_source_token_allowed"])
        self.assertTrue(node["fleet_private_source_read_credential_allowed"])
        self.assertFalse(node["public_strategy_authority"])
        self.assertFalse(node["public_contract_selection_authority"])
        self.assertFalse(node["cross_repo_github_token_assumed"])
        self.assertEqual(node["canonical_bot_dockerfile"], "Dockerfile.bot")

    def test_source_ingress_is_reusable_encrypted_vault(self):
        node = json.loads((ROOT / "config/route-contract.json").read_text())
        ingress = node["source_ingress"]
        self.assertEqual(
            ingress["canonical_transport"],
            "fleet_authority_exact_sha_encrypted_snapshot_vault",
        )
        self.assertEqual(ingress["private_source_repository"], "XoticHaze/mm-IBKR")
        self.assertEqual(
            ingress["runtime_consumer_repository"],
            "XoticHaze/mm-ibkr-runtime",
        )
        self.assertEqual(
            ingress["public_snapshot_repository"],
            "XoticHaze/mm-ibkr-runtime",
        )
        self.assertEqual(ingress["public_snapshot_branch"], "mmibkr-source-vault")
        self.assertEqual(ingress["source_sha_approval_authority"], "fleet_code_pin")
        self.assertEqual(
            ingress["snapshot_manifest_approval_authority"],
            "fleet_private_source_attestation_first_use_pin",
        )
        self.assertTrue(ingress["exact_source_sha_required"])
        self.assertTrue(ingress["manifest_sha256_required"])
        self.assertTrue(ingress["archive_digest_attestation_required"])
        self.assertEqual(
            ingress["fleet_secret_name"],
            "MMIBKR_PRIVATE_SOURCE_TOKEN",
        )
        self.assertEqual(
            ingress["fleet_secret_scope"],
            "XoticHaze/mm-IBKR contents:read",
        )
        self.assertFalse(ingress["runtime_receives_private_source_credential"])
        self.assertFalse(ingress["public_plaintext_allowed"])
        self.assertFalse(ingress["private_actions_required"])
        self.assertFalse(ingress["host_required"])
        self.assertFalse(ingress["connector_reconstruction_required"])
        self.assertEqual(ingress["status"], "finite_acceptance_proven")
        self.assertEqual(
            ingress["accepted_source_sha"],
            "61f0842b2de8709509453cb390310d246ea39ad3",
        )
        self.assertEqual(
            ingress["accepted_archive_sha256"],
            "b7346244fc8a8a7701a5c4fdce995d49df42509a5347f1959ce05c67faccb953",
        )
        self.assertEqual(
            ingress["accepted_manifest_sha256"],
            "8374203819a8ab71834629bc9a4528d7d98e8064f08c33268d88b03800cab510",
        )
        self.assertEqual(ingress["acceptance_run_id"], "35535783978")
        self.assertEqual(ingress["private_contract_suite"], "passed")
        self.assertEqual(ingress["dockerfile_bot_build"], "passed")
        self.assertFalse(ingress["broker_action"])
        self.assertFalse(ingress["candidate_fabricated"])

    def test_cloud_owner_uses_ephemeral_same_repo_control_token(self):
        node = json.loads((ROOT / "config/route-contract.json").read_text())
        control = node["cloud_owner_control"]
        self.assertEqual(
            control["owner_repository"],
            "XoticHaze/research-compute-public-",
        )
        self.assertEqual(
            control["broker_dispatch_repository"],
            "XoticHaze/research-compute-public-",
        )
        self.assertEqual(
            control["credential_source"],
            "github_actions_ephemeral_same_repo_token",
        )
        self.assertEqual(control["token_env_alias"], "IBKR_REMOTE_EXCHANGE_TOKEN")
        self.assertFalse(control["manual_pat_required"])
        self.assertFalse(control["cloudflare_secret_required"])
        self.assertFalse(control["token_persisted"])
        self.assertFalse(control["cross_repo_token_required"])
        self.assertFalse(control["live_execution_allowed"])

    def test_direct_fleet_stream_is_bootstrap_only(self):
        node = json.loads((ROOT / "config/route-contract.json").read_text())
        bootstrap = node["source_vault_bootstrap"]
        self.assertEqual(
            bootstrap["transport"],
            "fleet_authority_oidc_private_archive_stream",
        )
        self.assertEqual(
            bootstrap["purpose"],
            "create_missing_reusable_encrypted_snapshot_only",
        )
        self.assertTrue(
            bootstrap["private_source_fetch_skipped_when_snapshot_exists"]
        )
        self.assertFalse(bootstrap["runtime_private_repository_token_allowed"])
        self.assertTrue(bootstrap["runtime_public_repository_write_token_allowed"])
        self.assertFalse(bootstrap["public_plaintext_allowed"])
        self.assertFalse(bootstrap["live_execution_allowed"])

    def test_x25519_exchange_is_scoped_only_to_hot_b1_relay(self):
        node = json.loads((ROOT / "config/route-contract.json").read_text())
        relay = node["hot_b1_source_relay"]
        self.assertEqual(
            relay["transport"],
            "fleet_authority_oidc_x25519_source_exchange",
        )
        self.assertTrue(relay["genuine_candidate_required"])
        self.assertTrue(relay["same_attested_source_required"])
        self.assertFalse(relay["private_repository_producer_required"])
        self.assertFalse(
            node["broker_route"]["direct_runtime_repo_dispatch"]
        )


if __name__ == "__main__":
    unittest.main()
