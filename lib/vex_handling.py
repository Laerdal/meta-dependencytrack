import re

cve_match = re.compile(r"CVE:( CVE-\d{4}-\d+)+")

# Matches the last "CVE-YYYY-ID" in the file name, also if written
# in lowercase. Possible to have multiple CVE IDs in a single
# file name, but only the last one will be detected from the file name.
# However, patch files contents addressing multiple CVE IDs are supported
# (cve_match regular expression)
cve_file_name_match = re.compile(r".*(CVE-\d{4}-\d+)", re.IGNORECASE)


def _get_cve_from_filename(patch_file: str) -> str:
    """
    Get the last CVE ID from a patch file name, if present.
    """
    fname_match = cve_file_name_match.search(patch_file)
    return fname_match.group(1).upper() if fname_match else None


def _get_patch_text(patch_file: str) -> str | None:
    """
    Get the text content of a patch file, trying UTF-8 first and falling back to ISO-8859-1 if necessary.
    """
    # Remote patches won't be present and compressed patches won't be
    # unpacked, so say we're not scanning them
    if not os.path.isfile(patch_file):
        bb.note("%s is remote or compressed, not scanning content" % patch_file)
        return None

    with open(patch_file, "r", encoding="utf-8") as f:
        try:
            return f.read()
        except UnicodeDecodeError:
            bb.debug(1, "Failed to read patch %s using UTF-8 encoding, trying with iso8859-1" % patch_file)
            f.close()
            with open(patch_file, "r", encoding="iso8859-1") as f:
                return f.read()


patch_from_commit_pattern = re.compile(r"\bFrom\s+([0-9a-fA-F]{40})\b")
# commit subjects can be multiline, so we need to match the first line and any subsequent lines that are indented with whitespace
patch_subject_pattern = re.compile(r"^Subject:[ \t]*(.*(?:\r?\n[ \t]+.*)*)", re.MULTILINE)


def _get_patch_info(patch_text: str) -> tuple[str | None, str | None]:
    patch_hash_match = patch_from_commit_pattern.search(patch_text)
    patch_hash = patch_hash_match.group(1) if patch_hash_match else None

    commit_subject_match = patch_subject_pattern.search(patch_text)
    commit_subject = re.sub(r"\r?\n[ \t]+", " ", commit_subject_match.group(1)).strip() if commit_subject_match else None
    return patch_hash, commit_subject


def get_patch_evidence(d):
    """
    based on os.cve_check.get_patched_cves(d) but returns a dict of CVE IDs and the commit hash if available
    Get patches that solve CVEs using the "CVE: " tag.
    """

    import oe.patch

    patched_cves = {}
    patches = oe.patch.src_patches(d)
    bb.debug(2, "Scanning %d patches for CVEs" % len(patches))
    for url in patches:
        patch_file = bb.fetch.decodeurl(url)[2]

        cve_found = False

        # Check patch file name for CVE ID
        cve = _get_cve_from_filename(patch_file)
        if cve:
            if cve not in patched_cves:
                patched_cves[cve] = None
            bb.debug(2, "Found %s from patch file name %s" % (cve, patch_file))
            cve_found = True

        patch_text = _get_patch_text(patch_file)
        if patch_text is None:
            continue

        patch_hash, patch_subject = _get_patch_info(patch_text)

        # Search for one or more "CVE: " lines

        for match in cve_match.finditer(patch_text):
            # Get only the CVEs without the "CVE: " tag
            cves = patch_text[match.start() + 5:match.end()]
            for cve in cves.split():
                bb.debug(2, "Patch %s solves %s" % (patch_file, cve))
                if cve not in patched_cves or patch_hash:
                    patched_cves[cve] = (f"commit hash: {patch_hash}" if patch_hash else None) + (
                        f" ({patch_subject})" if patch_subject else "")
                cve_found = True

        if not cve_found:
            bb.debug(2, "Patch %s doesn't solve CVEs" % patch_file)

    # Search for additional patched CVEs
    from oe.cve_check import decode_cve_status

    for cve in (d.getVarFlags("CVE_STATUS") or {}):
        decoded = decode_cve_status(d, cve)
        if isinstance(decoded, dict):
            decoded_status = decoded.get("mapping", "")
            description = decoded.get("description", "")
        else:
            decoded_status, _, description = decoded

        if decoded_status == "Patched":
            bb.debug(2, "CVE %s is additionally patched" % cve)
            patched_cves[cve] = description

    return patched_cves


def add_ignored_vulnerability(vex: dict, cve_id: str, description: str) -> None:
    if next((v for v in vex["vulnerabilities"] if v["id"] == cve_id), None) is None:
        add_vulnerability(vex, cve_id, "resolved", "will_not_fix",
                          f"CVE_CHECK data: The vulnerability has been Ignored! {description}", "code_not_present")


def add_patched_vulnerability(vex: dict, cve_id: str, description: str) -> None:
    vulnerability = next(
        (v for v in vex["vulnerabilities"] if v["id"] == cve_id), None)
    if vulnerability is None:
        add_vulnerability(vex, cve_id, "resolved", "update",
                          f"CVE_CHECK data : The vulnerability has been Patched! {description}")
    else:  # (write to patched, even if already ignored)
        vulnerability["analysis"].update({"state": "resolved", "response": [
            "update"], "detail": f"CVE_CHECK data: The vulnerability has been Patched! {description}"})


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
