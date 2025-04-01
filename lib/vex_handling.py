def add_ignored_vulnerability(vex: dict, cve_id: str) -> None:
    if next((v for v in vex["vulnerabilities"] if v["id"] == cve_id), None) is None:
        add_vulnerability(vex, cve_id, "resolved", "will_not_fix",
                          "CVE_CHECK data: The vulnerability has been Ignored!", "code_not_present")


def add_patched_vulnerability(vex: dict, cve_id: str) -> None:
    vulnerability = next(
        (v for v in vex["vulnerabilities"] if v["id"] == cve_id), None)
    if vulnerability is None:
        add_vulnerability(vex, cve_id, "resolved", "update",
                          "CVE_CHECK data : The vulnerability has been Patched!")
    else:  # (write to patched, even if already ignored)
        vulnerability["analysis"].update({"state": "resolved", "response": [
            "update"], "detail": "CVE_CHECK data: The vulnerability has been Patched!"})


def add_vulnerability(vex: dict, cve_id: str, analysis_state: str, analysis_response: str, analysis_detail: str,
                      analysis_justification: str = None) -> None:
    vulnerability = {
        "id": cve_id,
        "source": {"name": "NVD", "url": "https://nvd.nist.gov/"},
        "analysis": {"state": analysis_state, "response": [analysis_response], "detail": analysis_detail},
        "affects": [{"ref": vex["metadata"]["component"]["bom-ref"]}]
    }

    if analysis_justification:
        vulnerability["analysis"]["justification"] = analysis_justification

    vex["vulnerabilities"].append(vulnerability)
