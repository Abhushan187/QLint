"""Harvest Now, Decrypt Later (HNDL) risk model for QLint.

HNDL is the attack where an adversary records encrypted traffic today and
stores it until a cryptographically relevant quantum computer (CRQC) can
break the key exchange that protected it. Whether that matters for a given
codebase depends on three numbers:

  * how long the data stays worth reading (shelf life),
  * how long until a CRQC plausibly exists,
  * how long this codebase would take to migrate off vulnerable crypto.

The middle number is a genuine unknown, so this module never commits to one
answer: every calculation is also reported across all three CRQC scenarios so
the caller can see how much of the verdict rests on that estimate.

Pure data + arithmetic: no network calls, no database, no framework imports.
It reads a scan report that scanner_engine already produced and never changes
how scanning works.
"""

from datetime import datetime, timezone

# How long data of each kind stays valuable to an attacker after capture.
# Values are typical retention/secrecy horizons, not legal guarantees.
DATA_SENSITIVITY_PROFILES: dict[str, dict] = {
    "session_tokens": {
        "label": "Session Tokens / Ephemeral Auth",
        "shelf_life_years": 0.1,
    },
    "api_keys": {
        "label": "API Keys / Service Credentials",
        "shelf_life_years": 2,
    },
    "financial_records": {
        "label": "Financial Records",
        "shelf_life_years": 7,
    },
    "personal_data": {
        "label": "Personal / Customer Data (PII)",
        "shelf_life_years": 15,
    },
    "healthcare_records": {
        "label": "Healthcare Records",
        "shelf_life_years": 50,
    },
    "government_classified": {
        "label": "Government / Classified Data",
        "shelf_life_years": 75,
    },
    "trade_secrets": {
        "label": "Trade Secrets / IP",
        "shelf_life_years": 25,
    },
}

# Published CRQC arrival estimates disagree by more than a decade. These are
# offsets from the date the calculation runs, never absolute years, so the
# model does not silently go stale as calendar years pass.
CRQC_SCENARIOS: dict[str, dict] = {
    "aggressive": {
        "label": "Aggressive (early estimates)",
        "years_from_now": 5,
    },
    "moderate": {
        "label": "Moderate (consensus estimate)",
        "years_from_now": 10,
    },
    "conservative": {
        "label": "Conservative (skeptical estimates)",
        "years_from_now": 15,
    },
}

# Migration effort tiers, keyed on the count of critical findings.
#
# THIS IS A COARSE ESTIMATE, NOT A PREDICTION. It is a step function over one
# input, and it cannot see team size, release cadence, how much of the crypto
# sits behind an internal abstraction, or whether a dependency has shipped a
# PQC option yet. Its job is to answer "is the migration measured in months or
# in years", which is the only resolution the CRQC estimate can support
# anyway. Every text field this module produces says so.
_MIGRATION_TIERS: tuple[tuple[int, float], ...] = (
    (0, 0.0),  # nothing vulnerable to migrate
    (10, 0.5),
    (50, 1.5),
    (150, 3.0),
)
_MIGRATION_MAX_YEARS = 5.0  # more than 150 critical findings

_ESTIMATE_CAVEAT = (
    "These figures are deliberately coarse estimates, not predictions: the "
    "migration effort is inferred from finding counts alone, and the CRQC "
    "arrival date is genuinely unknown."
)


def _valid_keys_error(field: str, valid: list[str], given: str) -> ValueError:
    return ValueError(
        f"Unknown {field}: {given!r}. Valid options: {', '.join(sorted(valid))}"
    )


def estimate_migration_time_years(scan_report: dict) -> float:
    """Estimate migration time in years from a scan report's severity mix.

    Tiered on critical findings, which are the ones that actually force a
    code change; warnings and safe findings do not move the estimate. A
    report missing its severity summary is read as zero criticals rather
    than raising, so a partial report still yields a usable answer.
    """
    summary = scan_report.get("severity_summary") or {}
    try:
        critical = int(summary.get("critical", 0) or 0)
    except (TypeError, ValueError):
        critical = 0
    if critical <= 0:
        return 0.0
    for upper_bound, years in _MIGRATION_TIERS:
        if critical <= upper_bound:
            return years
    return _MIGRATION_MAX_YEARS


def _round(value: float) -> float:
    return round(float(value), 2)


def _scenario_row(scenario_key: str, migration_time_years: float,
                  shelf_life_years: float) -> dict:
    scenario = CRQC_SCENARIOS[scenario_key]
    risk_window = scenario["years_from_now"] - migration_time_years
    return {
        "scenario": scenario_key,
        "label": scenario["label"],
        "risk_window_years": _round(risk_window),
        "exposed": risk_window < 0 or shelf_life_years > risk_window,
    }


def _verdict(
    label: str,
    shelf_life_years: float,
    scenario_label: str,
    crqc_years: float,
    crqc_year: int,
    migration_time_years: float,
    risk_window_years: float,
    total_findings: int,
    critical_findings: int,
) -> str:
    """One paragraph of plain language explaining the number."""
    scan_context = (
        f"This scan found {critical_findings} critical "
        f"{'finding' if critical_findings == 1 else 'findings'} "
        f"across {total_findings} total, which puts the migration at roughly "
        f"{migration_time_years} years."
    )

    if migration_time_years == 0:
        return (
            f"{scan_context} Nothing quantum-vulnerable was detected, so there "
            f"is no migration backlog standing between this codebase and the "
            f"estimated {crqc_years:g}-year CRQC horizon under the "
            f"{scenario_label} scenario. {label} data captured today stays "
            f"sensitive for about {shelf_life_years:g} years"
            + (
                f", which still outlasts that horizon, so anything encrypted by "
                f"code outside this scan's reach remains worth checking."
                if shelf_life_years > risk_window_years
                else ", which is shorter than that horizon."
            )
        )

    if risk_window_years < 0:
        return (
            f"{scan_context} That is longer than the {crqc_years:g} years until "
            f"a CRQC is expected under the {scenario_label} scenario, leaving a "
            f"risk window of {risk_window_years} years. The window is negative: "
            f"the migration would not finish before the threat arrives, so data "
            f"encrypted by this codebase today is exposed no matter how short "
            f"its useful life. {label} data is the least of the problem here, "
            f"because every kind of data this system handles is affected."
        )

    if shelf_life_years > risk_window_years:
        return (
            f"{scan_context} Subtracting that from the {crqc_years:g} years until "
            f"a CRQC is expected under the {scenario_label} scenario leaves a "
            f"{risk_window_years}-year window in which data can be safely "
            f"encrypted with what is in this repository today. {label} data "
            f"stays sensitive for about {shelf_life_years:g} years, which "
            f"outlasts that window. Traffic an adversary records today would "
            f"still be worth decrypting when a CRQC arrives around {crqc_year}."
        )

    return (
        f"{scan_context} Subtracting that from the {crqc_years:g} years until a "
        f"CRQC is expected under the {scenario_label} scenario leaves a "
        f"{risk_window_years}-year window in which data can be safely encrypted "
        f"with what is in this repository today. {label} data stays sensitive "
        f"for about {shelf_life_years:g} years, which is inside that window: "
        f"recorded traffic would have lost its value before a CRQC around "
        f"{crqc_year} could read it."
    )


def _recommendation(
    exposed: bool,
    risk_window_years: float,
    migration_time_years: float,
    critical_findings: int,
    scenario_agreement: str,
) -> str:
    """One paragraph of concrete next steps."""
    if risk_window_years < 0:
        return (
            f"Treat this as urgent and parallel, not sequential. Do not wait for "
            f"a full migration: put a hybrid key exchange (X25519 + ML-KEM) in "
            f"front of the {critical_findings} critical findings first, so new "
            f"traffic stops accumulating exposure while the rest of the work "
            f"proceeds. Prioritize whatever terminates external connections and "
            f"whatever writes long-lived records, and re-scan after each "
            f"tranche to watch the estimate move. {scenario_agreement} "
            f"{_ESTIMATE_CAVEAT}"
        )
    if exposed:
        return (
            f"Start the migration now rather than scheduling it. With roughly "
            f"{migration_time_years} years of work against a "
            f"{risk_window_years}-year window, the schedule only holds if "
            f"nothing slips. Begin with the {critical_findings} critical "
            f"findings, adopting hybrid key exchange (X25519 + ML-KEM) for "
            f"anything that carries data over the network and ML-DSA for "
            f"signatures, and inventory where this data is retained so you know "
            f"what a past capture would already contain. {scenario_agreement} "
            f"{_ESTIMATE_CAVEAT}"
        )
    if critical_findings == 0:
        return (
            f"No migration backlog was detected, so the practical work is "
            f"keeping it that way: re-scan on each release so new dependencies "
            f"cannot reintroduce classical-only crypto, and confirm that "
            f"systems outside this repository (TLS termination, managed "
            f"databases, third-party APIs) have their own PQC path. "
            f"{scenario_agreement} {_ESTIMATE_CAVEAT}"
        )
    return (
        f"This data class is not exposed on these assumptions, so plan the "
        f"migration rather than emergency-patching it. Fold the "
        f"{critical_findings} critical findings into normal release work over "
        f"the next {migration_time_years} years, and re-run this calculation "
        f"against your longest-lived data class as well, since a single system "
        f"usually handles several. {scenario_agreement} {_ESTIMATE_CAVEAT}"
    )


def _scenario_agreement(all_scenarios: list[dict]) -> str:
    """State whether the verdict survives the CRQC estimate being wrong."""
    exposed_count = sum(1 for row in all_scenarios if row["exposed"])
    if exposed_count == len(all_scenarios):
        return (
            "This verdict does not depend on the CRQC estimate: all three "
            "scenarios come out exposed."
        )
    if exposed_count == 0:
        return (
            "This verdict does not depend on the CRQC estimate: no scenario "
            "comes out exposed."
        )
    return (
        f"The verdict is sensitive to the CRQC estimate: {exposed_count} of "
        f"{len(all_scenarios)} scenarios come out exposed, so treat the "
        "scenario table as part of the answer rather than picking one number."
    )


def calculate_hndl_risk(
    scan_report: dict,
    data_sensitivity: str,
    crqc_scenario: str = "moderate",
) -> dict:
    """Score a scan report for Harvest Now, Decrypt Later exposure.

    Raises ValueError (listing the valid keys) when either selector is
    unknown — a caller passing a bad key needs to hear about it, not receive
    a confident answer computed from a silent default. Any other malformed
    input degrades to zero findings instead of raising.
    """
    if data_sensitivity not in DATA_SENSITIVITY_PROFILES:
        raise _valid_keys_error(
            "data_sensitivity", list(DATA_SENSITIVITY_PROFILES), data_sensitivity
        )
    if crqc_scenario not in CRQC_SCENARIOS:
        raise _valid_keys_error("crqc_scenario", list(CRQC_SCENARIOS), crqc_scenario)

    profile = DATA_SENSITIVITY_PROFILES[data_sensitivity]
    scenario = CRQC_SCENARIOS[crqc_scenario]
    shelf_life_years = float(profile["shelf_life_years"])
    crqc_years_from_now = float(scenario["years_from_now"])

    report = scan_report if isinstance(scan_report, dict) else {}
    migration_time_years = estimate_migration_time_years(report)
    summary = report.get("severity_summary") or {}
    critical_findings = int(summary.get("critical", 0) or 0)
    total_findings = int(report.get("total_findings", 0) or 0)

    risk_window_years = crqc_years_from_now - migration_time_years
    # A negative window means the migration outlasts the threat timeline, so
    # exposure no longer depends on shelf life at all.
    exposed = risk_window_years < 0 or shelf_life_years > risk_window_years

    all_scenarios = [
        _scenario_row(key, migration_time_years, shelf_life_years)
        for key in CRQC_SCENARIOS
    ]
    crqc_year = datetime.now(timezone.utc).year + int(round(crqc_years_from_now))

    return {
        "data_sensitivity": data_sensitivity,
        "data_sensitivity_label": profile["label"],
        "shelf_life_years": _round(shelf_life_years),
        "crqc_scenario": crqc_scenario,
        "crqc_scenario_label": scenario["label"],
        "crqc_years_from_now": _round(crqc_years_from_now),
        "crqc_estimated_year": crqc_year,
        "migration_time_years": _round(migration_time_years),
        "risk_window_years": _round(risk_window_years),
        "exposed": exposed,
        "verdict": _verdict(
            profile["label"],
            shelf_life_years,
            scenario["label"],
            crqc_years_from_now,
            crqc_year,
            _round(migration_time_years),
            _round(risk_window_years),
            total_findings,
            critical_findings,
        ),
        "recommendation": _recommendation(
            exposed,
            _round(risk_window_years),
            _round(migration_time_years),
            critical_findings,
            _scenario_agreement(all_scenarios),
        ),
        "all_scenarios": all_scenarios,
    }


if __name__ == "__main__":
    fake_report = {
        "severity_summary": {"critical": 72, "warning": 4, "safe": 8, "info": 0},
        "total_findings": 84
    }
    result = calculate_hndl_risk(fake_report, "healthcare_records", "moderate")
    assert result["exposed"] == True  # 72 criticals -> 3yr migration,
                                        # moderate CRQC 10yr -> window 7yr,
                                        # healthcare shelf life 50yr -> exposed
    assert len(result["all_scenarios"]) == 3
    print(f"hndl_calculator.py self-test passed")
    print(f"  Verdict: {result['verdict']}")
    print(f"  Risk window: {result['risk_window_years']} years")
