"""
Automated Golden Benchmark Test Suite for ClarityTI.

Executes all positive and negative benchmark cases and calculates:
- Precision
- Recall
- F1 Score
- False Positive Rate (FPR)
- False Negative Rate (FNR)
- Teams Alert Precision & Recall
"""
import pytest
try:
    from backend.tests.golden_dataset import GOLDEN_BENCHMARK_CASES
except ImportError:
    from tests.golden_dataset import GOLDEN_BENCHMARK_CASES

from app.services.teams_service import (
    TeamAlertDecisionEngine,
    is_critical_actionable_incident,
    determine_breach_status,
    extract_breached_company,
    extract_threat_actor,
    extract_claimed_records
)


def test_golden_benchmark_precision_and_recall():
    """
    Evaluates every case in GOLDEN_BENCHMARK_CASES against the 4-Stage Decision Engine.
    Enforces a 100% precision and 100% recall benchmark gate on the golden dataset.
    """
    total_cases = len(GOLDEN_BENCHMARK_CASES)
    true_positives = 0
    false_positives = 0
    true_negatives = 0
    false_negatives = 0

    results = []

    for case in GOLDEN_BENCHMARK_CASES:
        expected = case["expected"]
        art = {
            "title": case["title"],
            "summary": case["summary"],
            "content_clean": case["content_clean"],
            "source_name": case.get("source_name", "Security Feed"),
            "claim_status": expected.get("claim_status"),
            "claimed_records_count": expected.get("claimed_records_count"),
            "target_company": expected.get("target_company"),
            "threat_actor": expected.get("threat_actor"),
        }

        eval_result = TeamAlertDecisionEngine.evaluate(art)
        actual_decision = eval_result["decision"]
        expected_decision = expected["decision"]
        is_actionable = is_critical_actionable_incident(art)

        is_expected_positive = (expected_decision == "TEAM_ALERT")
        is_actual_positive = (actual_decision == "TEAM_ALERT")

        if is_expected_positive and is_actual_positive:
            true_positives += 1
            status = "TP (CORRECT ALERT)"
        elif not is_expected_positive and not is_actual_positive:
            true_negatives += 1
            status = "TN (CORRECT FILTER)"
        elif not is_expected_positive and is_actual_positive:
            false_positives += 1
            status = "FP (UNWANTED ALERT)"
        else:
            false_negatives += 1
            status = "FN (MISSED ALERT)"

        results.append({
            "id": case["id"],
            "expected": expected_decision,
            "actual": actual_decision,
            "score": eval_result["score"],
            "status": status
        })

    # Calculations
    precision = (true_positives / (true_positives + false_positives)) if (true_positives + false_positives) > 0 else 0.0
    recall = (true_positives / (true_positives + false_negatives)) if (true_positives + false_negatives) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    fpr = (false_positives / (false_positives + true_negatives)) if (false_positives + true_negatives) > 0 else 0.0
    fnr = (false_negatives / (false_negatives + true_positives)) if (false_negatives + true_positives) > 0 else 0.0

    print(f"\n=================================================================")
    print(f"📊 GOLDEN BENCHMARK RESULTS ({total_cases} CASES EVALUATED)")
    print(f"=================================================================")
    print(f"  True Positives (TP) : {true_positives}")
    print(f"  True Negatives (TN) : {true_negatives}")
    print(f"  False Positives (FP): {false_positives}")
    print(f"  False Negatives (FN): {false_negatives}")
    print(f"  -------------------------------------------------------------")
    print(f"  Teams Alert Precision: {precision * 100:.1f}%")
    print(f"  Teams Alert Recall   : {recall * 100:.1f}%")
    print(f"  F1-Score             : {f1 * 100:.1f}%")
    print(f"  False Positive Rate  : {fpr * 100:.1f}%")
    print(f"  False Negative Rate  : {fnr * 100:.1f}%")
    print(f"=================================================================\n")

    # Strict Golden Benchmark assertions
    assert false_positives == 0, f"False positives detected on golden dataset: {[r for r in results if 'FP' in r['status']]}"
    assert false_negatives == 0, f"False negatives detected on golden dataset: {[r for r in results if 'FN' in r['status']]}"
    assert precision == 1.0, f"Expected 100% precision on golden dataset, got {precision}"
    assert recall == 1.0, f"Expected 100% recall on golden dataset, got {recall}"


def test_positive_cases_meet_evidence_scores():
    """Verify that all positive cases meet their expected minimum evidence scores."""
    for case in GOLDEN_BENCHMARK_CASES:
        if case["expected"]["decision"] == "TEAM_ALERT":
            art = {
                "title": case["title"],
                "summary": case["summary"],
                "content_clean": case["content_clean"],
                "source_name": case.get("source_name", "Security Feed"),
                "claim_status": case["expected"].get("claim_status"),
                "claimed_records_count": case["expected"].get("claimed_records_count"),
                "target_company": case["expected"].get("target_company"),
                "threat_actor": case["expected"].get("threat_actor"),
            }
            eval_res = TeamAlertDecisionEngine.evaluate(art)
            min_score = case["expected"].get("min_evidence_score", 50)
            assert eval_res["score"] >= min_score, f"Case {case['id']} score {eval_res['score']} < min {min_score}"
            assert eval_res["decision"] == "TEAM_ALERT"


def test_negative_cases_are_strictly_website_only():
    """Verify that all negative cases are strictly WEBSITE_ONLY and never TEAM_ALERT."""
    for case in GOLDEN_BENCHMARK_CASES:
        if case["expected"]["decision"] == "WEBSITE_ONLY":
            art = {
                "title": case["title"],
                "summary": case["summary"],
                "content_clean": case["content_clean"],
                "source_name": case.get("source_name", "Security Feed"),
                "claim_status": case["expected"].get("claim_status", "claimed"),
            }
            eval_res = TeamAlertDecisionEngine.evaluate(art)
            assert eval_res["decision"] == "WEBSITE_ONLY", f"Case {case['id']} failed to be WEBSITE_ONLY: {eval_res}"
            assert not is_critical_actionable_incident(art), f"Case {case['id']} erroneously marked actionable"
