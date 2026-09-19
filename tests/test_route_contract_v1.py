from __future__ import annotations

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class RouteContractTests(unittest.TestCase):
    def test_authority_split_is_fail_closed(self):
        node = json.loads((ROOT / "config/route-contract.json").read_text())
        self.assertEqual(node["schema"], "mmibkr.public_runtime_route_contract.v1")
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
        self.assertEqual(
            node["source_exchange"]["transport"],
            "fleet_authority_oidc_x25519",
        )
        self.assertTrue(
            node["source_exchange"]["private_attestation_required"]
        )
        self.assertFalse(
            node["broker_route"]["direct_runtime_repo_dispatch"]
        )


if __name__ == "__main__":
    unittest.main()
