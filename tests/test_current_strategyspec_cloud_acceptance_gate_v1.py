from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/mmibkr-selected-runtime-cloud-r1.yml"

EXPECTED = {
    "MNQ": "00658020a4676b67a25f0cbb74e01ea600336d0ca485764e03eaefd34f48254a",
    "AMAT": "f5063f36984199aa86836852824b91cab3651aab255647f8fac47e4ebc6d885a",
    "APH": "8b831cce20d82256632269b386251afa0f0723f5fdbfb6e938d6249a1e6d5bfa",
}


def test_finite_cloud_acceptance_calls_strategyspec_continuity_contracts():
    text = WORKFLOW.read_text(encoding="utf-8")
    for module in (
        "tests.test_selected_runtime_strategy_spec_integrity_v1",
        "tests.test_selected_runtime_strategy_identity_continuity_14th31ht",
        "tests.test_strategy_identity_guarded_submit_continuity_14th31hv",
        "tests.test_strategy_spec_runtime_persistence_14th31ho",
    ):
        assert module in text


def test_finite_cloud_acceptance_pins_current_selected_runtime_digests():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "MMIBKR_CURRENT_STRATEGYSPEC_TRIO_PROVEN=1" in text
    assert "selected_runtime_strategy_spec_trio_proven':True" in text
    for symbol, digest in EXPECTED.items():
        assert digest in text
        assert f"MMIBKR_STRATEGYSPEC_" in text
    assert "live_submit_enabled" in text
    assert "live policy unexpectedly enabled" in text

def test_selected_runtime_consumes_vault_without_inline_first_use_bootstrap():
    selected = WORKFLOW.read_text(encoding="utf-8")
    dedicated = (
        ROOT / ".github/workflows/mmibkr-source-vault-bootstrap-r1.yml"
    ).read_text(encoding="utf-8")
    assert "source-vault-bootstrap:" not in selected
    assert "mmibkr_fleet_source_vault_bootstrap_v1.py" not in selected
    assert "needs: [source-contract]" in selected
    assert "mmibkr_fleet_source_vault_bootstrap_v1.py" in dedicated
    assert "Bootstrap reusable encrypted source-vault snapshot through Fleet" in dedicated

