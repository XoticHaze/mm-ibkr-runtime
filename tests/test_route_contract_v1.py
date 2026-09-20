from __future__ import annotations

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class RouteContractTests(unittest.TestCase):
    def test_authority_split_is_fail_closed(self):
        node = json.loads((ROOT / "config/route-contract.json").read_text())
        self.assertEqual(node["schema"], "mmibkr.public_runtime_route_contract.v2")
        self.assertEqual(node["runtime_repository"], "XoticHaze/mm-ibkr-runtime")
        self.assertEqual(node["private_authority_repository"], "XoticHaze/mm-IBKR")
        self.assertEqual(
            node["broker_compute_repository"],
            "XoticHaze/research-compute-public-",
        )
        self.assertEqual(node["canonical_b1_ref"], "ibkr-b1-authority-v1")
        self.assertFalse(node["live_trading_allowed"])
        self.assertFalse(node["direct_ibkr_credentials_allowed"])
        self.assertFalse(node["private_source_pat_allowed"])
        self.assertFalse(node["public_strategy_authority"])
        self.assertFalse(node["public_contract_selection_authority"])
        self.assertFalse(node["cross_repo_github_token_assumed"])
        self.assertEqual(node["canonical_bot_dockerfile"], "Dockerfile.bot")

    def test_source_ingress_is_reusable_vault_not_private_actions_exchange(self):
        node = json.loads((ROOT / "config/route-contract.json").read_text())
        ingress = node["source_ingress"]
        self.assertEqual(
            ingress["canonical_transport"],
            "fleet_authority_exact_sha_encrypted_snapshot_vault",
        )
        self.assertEqual(
            ingress["vault_authority_repository"],
            "XoticHaze/research-compute-public-",
        )
        self.assertEqual(
            ingress["runtime_consumer_repository"],
            "XoticHaze/mm-ibkr-runtime",
        )
        self.assertTrue(ingress["exact_source_sha_required"])
        self.assertTrue(ingress["manifest_sha256_required"])
        self.assertFalse(ingress["public_plaintext_allowed"])
        self.assertFalse(ingress["private_actions_required"])
        self.assertFalse(ingress["private_repository_token_allowed"])
        self.assertEqual(
            ingress["publisher"],
            "local_file_capable_ciphertext_only_publisher",
        )
        self.assertEqual(
            ingress["public_snapshot_repository"],
            "XoticHaze/research-compute-public-",
        )
        self.assertEqual(ingress["public_snapshot_branch"], "mmibkr-source-vault")
        self.assertEqual(
            ingress["runtime_workflow"],
            ".github/workflows/mmibkr-selected-runtime-cloud-r1.yml",
        )
        self.assertEqual(
            ingress["status"],
            "producer_binding_implemented_real_snapshot_pending",
        )

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
