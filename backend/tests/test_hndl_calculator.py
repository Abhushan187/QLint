"""Tests for hndl_calculator.calculate_hndl_risk (Harvest Now, Decrypt Later)."""

import pytest

from hndl_calculator import (
    CRQC_SCENARIOS,
    DATA_SENSITIVITY_PROFILES,
    calculate_hndl_risk,
    estimate_migration_time_years,
)


def report(critical: int, total: int | None = None) -> dict:
    """A minimal scan report carrying only what the model reads."""
    return {
        "severity_summary": {
            "critical": critical,
            "warning": 0,
            "safe": 0,
            "info": 0,
        },
        "total_findings": critical if total is None else total,
    }


class TestMigrationTimeTiers:
    @pytest.mark.parametrize(
        "critical,expected",
        [
            (0, 0.0),
            (1, 0.5),
            (10, 0.5),
            (11, 1.5),
            (50, 1.5),
            (51, 3.0),
            (150, 3.0),
            (151, 5.0),
            (5000, 5.0),
        ],
    )
    def test_each_tier_computes_the_documented_value(self, critical, expected):
        assert estimate_migration_time_years(report(critical)) == expected

    def test_tier_reaches_the_result_dict(self):
        result = calculate_hndl_risk(report(72), "personal_data", "moderate")
        assert result["migration_time_years"] == 3.0

    def test_a_report_without_a_severity_summary_reads_as_zero(self):
        assert estimate_migration_time_years({}) == 0.0
        assert estimate_migration_time_years({"severity_summary": None}) == 0.0

    def test_a_non_numeric_critical_count_does_not_raise(self):
        assert estimate_migration_time_years(
            {"severity_summary": {"critical": "lots"}}
        ) == 0.0

    def test_only_critical_findings_move_the_estimate(self):
        noisy = {
            "severity_summary": {
                "critical": 0,
                "warning": 400,
                "safe": 400,
                "info": 400,
            },
            "total_findings": 1200,
        }
        assert estimate_migration_time_years(noisy) == 0.0


class TestZeroCriticalFindings:
    def test_migration_time_is_zero_and_window_is_the_full_crqc_horizon(self):
        result = calculate_hndl_risk(report(0), "personal_data", "moderate")
        assert result["migration_time_years"] == 0.0
        assert result["risk_window_years"] == 10.0

    def test_exposure_then_depends_only_on_shelf_life_vs_crqc_horizon(self):
        # 15-year PII outlasts the 10-year horizon; 2-year API keys do not.
        exposed = calculate_hndl_risk(report(0), "personal_data", "moderate")
        assert exposed["exposed"] is True
        assert exposed["shelf_life_years"] > exposed["crqc_years_from_now"]

        clear = calculate_hndl_risk(report(0), "api_keys", "moderate")
        assert clear["exposed"] is False
        assert clear["shelf_life_years"] < clear["crqc_years_from_now"]


class TestExposureVerdict:
    def test_high_critical_count_and_long_shelf_life_is_exposed(self):
        result = calculate_hndl_risk(report(72, 84), "healthcare_records", "moderate")
        assert result["exposed"] is True
        assert result["migration_time_years"] == 3.0
        assert result["risk_window_years"] == 7.0
        assert result["shelf_life_years"] == 50.0

    def test_low_critical_count_and_short_shelf_life_is_not_exposed(self):
        result = calculate_hndl_risk(report(3), "session_tokens", "moderate")
        assert result["exposed"] is False
        assert result["migration_time_years"] == 0.5
        assert result["risk_window_years"] == 9.5
        assert result["shelf_life_years"] == 0.1

    def test_the_same_scan_flips_verdict_on_the_sensitivity_selector(self):
        scan = report(72, 84)
        assert calculate_hndl_risk(scan, "healthcare_records", "moderate")["exposed"]
        assert not calculate_hndl_risk(scan, "session_tokens", "moderate")["exposed"]

    def test_the_same_scan_flips_verdict_on_the_crqc_selector(self):
        # 7-year financial records: exposed on the 5-year horizon (window 2),
        # clear on the 15-year one (window 12).
        scan = report(72, 84)
        assert calculate_hndl_risk(scan, "financial_records", "aggressive")["exposed"]
        assert not calculate_hndl_risk(
            scan, "financial_records", "conservative"
        )["exposed"]


class TestNegativeRiskWindow:
    """Migration alone outlasting the CRQC timeline is the worst case.

    The shipped constants cannot reach a negative window: the largest
    migration estimate (5 years) exactly equals the shortest CRQC horizon
    (aggressive, 5 years). So the boundary is tested against the real
    constants, and the sub-zero case is reached by patching one scenario.
    """

    def test_zero_window_still_exposes_even_the_shortest_shelf_life(self):
        result = calculate_hndl_risk(report(200, 240), "session_tokens", "aggressive")
        assert result["migration_time_years"] == 5.0
        assert result["risk_window_years"] == 0.0
        # 0.1-year session tokens outlast a zero-length window.
        assert result["exposed"] is True

    def test_negative_window_forces_exposure_and_says_so(self, monkeypatch):
        monkeypatch.setitem(
            CRQC_SCENARIOS,
            "aggressive",
            {"label": "Aggressive (early estimates)", "years_from_now": 3},
        )
        result = calculate_hndl_risk(report(200, 240), "session_tokens", "aggressive")
        assert result["risk_window_years"] == -2.0
        # Exposed despite the shortest shelf life on the menu (0.1 years).
        assert result["exposed"] is True
        assert "negative" in result["verdict"].lower()
        assert "would not finish before" in result["verdict"]
        assert "no matter how short" in result["verdict"]
        # The worst case must not be softened into a scheduling suggestion.
        assert "urgent" in result["recommendation"].lower()

    def test_negative_window_marks_every_scenario_row_exposed(self, monkeypatch):
        monkeypatch.setitem(
            CRQC_SCENARIOS,
            "aggressive",
            {"label": "Aggressive (early estimates)", "years_from_now": 3},
        )
        result = calculate_hndl_risk(report(200, 240), "session_tokens", "aggressive")
        aggressive = result["all_scenarios"][0]
        assert aggressive["risk_window_years"] == -2.0
        assert aggressive["exposed"] is True


class TestInvalidInput:
    def test_invalid_data_sensitivity_raises_with_valid_options(self):
        with pytest.raises(ValueError) as exc:
            calculate_hndl_risk(report(1), "nuclear_codes", "moderate")
        message = str(exc.value)
        assert "nuclear_codes" in message
        for key in DATA_SENSITIVITY_PROFILES:
            assert key in message

    def test_invalid_crqc_scenario_raises_with_valid_options(self):
        with pytest.raises(ValueError) as exc:
            calculate_hndl_risk(report(1), "api_keys", "tomorrow")
        message = str(exc.value)
        assert "tomorrow" in message
        for key in CRQC_SCENARIOS:
            assert key in message

    def test_a_malformed_report_does_not_raise(self):
        result = calculate_hndl_risk({"nonsense": True}, "api_keys", "moderate")
        assert result["migration_time_years"] == 0.0
        result = calculate_hndl_risk(None, "api_keys", "moderate")
        assert result["migration_time_years"] == 0.0


class TestAllScenarios:
    def test_always_exactly_three_entries(self):
        for sensitivity in DATA_SENSITIVITY_PROFILES:
            for scenario in CRQC_SCENARIOS:
                result = calculate_hndl_risk(report(72), sensitivity, scenario)
                assert len(result["all_scenarios"]) == 3

    def test_covers_every_named_scenario_with_the_required_fields(self):
        rows = calculate_hndl_risk(report(72), "personal_data", "moderate")[
            "all_scenarios"
        ]
        assert [row["scenario"] for row in rows] == list(CRQC_SCENARIOS)
        for row in rows:
            assert set(row) >= {"scenario", "risk_window_years", "exposed"}
            assert isinstance(row["exposed"], bool)

    def test_scenario_rows_do_not_depend_on_the_selected_scenario(self):
        # Selecting a scenario changes the headline, never the table.
        scan = report(72, 84)
        first = calculate_hndl_risk(scan, "personal_data", "aggressive")
        second = calculate_hndl_risk(scan, "personal_data", "conservative")
        assert first["all_scenarios"] == second["all_scenarios"]

    def test_selected_scenario_row_matches_the_headline_numbers(self):
        for scenario in CRQC_SCENARIOS:
            result = calculate_hndl_risk(report(72), "financial_records", scenario)
            row = next(
                r for r in result["all_scenarios"] if r["scenario"] == scenario
            )
            assert row["risk_window_years"] == result["risk_window_years"]
            assert row["exposed"] == result["exposed"]


class TestResultShape:
    REQUIRED = {
        "data_sensitivity",
        "data_sensitivity_label",
        "shelf_life_years",
        "crqc_scenario",
        "crqc_years_from_now",
        "migration_time_years",
        "risk_window_years",
        "exposed",
        "verdict",
        "recommendation",
        "all_scenarios",
    }

    def test_every_required_field_is_present(self):
        result = calculate_hndl_risk(report(72, 84), "trade_secrets", "moderate")
        assert self.REQUIRED <= set(result)
        assert result["data_sensitivity"] == "trade_secrets"
        assert result["data_sensitivity_label"] == "Trade Secrets / IP"
        assert result["crqc_scenario"] == "moderate"

    def test_defaults_to_the_moderate_scenario(self):
        assert (
            calculate_hndl_risk(report(1), "api_keys")["crqc_scenario"] == "moderate"
        )

    def test_text_fields_are_prose_and_admit_the_estimate_is_coarse(self):
        result = calculate_hndl_risk(report(72, 84), "healthcare_records", "moderate")
        assert len(result["verdict"]) > 80
        assert len(result["recommendation"]) > 80
        assert "estimate" in result["recommendation"].lower()

    def test_estimated_crqc_year_tracks_the_current_year(self):
        from datetime import datetime, timezone

        result = calculate_hndl_risk(report(0), "api_keys", "moderate")
        assert (
            result["crqc_estimated_year"]
            == datetime.now(timezone.utc).year + 10
        )
