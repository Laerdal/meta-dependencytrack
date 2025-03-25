import pathlib
import re
import hashlib
import uuid


def get_bom_ref(value) -> str:
    return str(uuid.UUID(hashlib.md5(value.encode()).hexdigest()))


def get_cpe_ids(cve_product: str, version: str, part: str) -> list:
    """
    Get list of CPE identifiers for the given product and version
    """

    cpe_ids = []
    for product in cve_product.split():
        # CVE_PRODUCT in recipes may include vendor information for CPE identifiers. If not,
        # use wildcard for vendor.
        if ":" in product:
            vendor, product = product.split(":", 1)
        else:
            vendor = "*"

        cpe_id = 'cpe:2.3:{}:{}:{}:{}:*:*:*:*:*:*:*'.format(
            part, vendor, product, version)
        cpe_ids.append(type('', (object,), {
            "cpe": cpe_id, "product": product, "vendor": vendor if vendor != "*" else ""})())

    return cpe_ids


def get_references(src_uris: list) -> list:
    pattern = re.compile(
        r"https?://[a-z.]*/[a-z.\-/_]*[a-z.\-_].(tar.([gxl]?z|bz2)|tgz)")
    refs = []
    for src in src_uris:
        if src.startswith("git://") or src.endswith(".git"):
            refs.append({"type": "vcs", "url": src})

        elif pattern.match(src):
            refs.append({"type": "source-distribution", "url": src})

        elif src.startswith("http://") or src.startswith("https://"):
            refs.append({"type": "website", "url": src})

    return refs


def get_licenses(d):
    license_conversion_map = {"GPLv2+": "GPL-2.0-or-later", "GPLv2": "GPL-2.0", "LGPLv2": "LGPL-2.0",
                              "LGPLv2+": "LGPL-2.0-or-later", "LGPLv2.1+": "LGPL-2.1-or-later", "LGPLv2.1": "LGPL-2.1"}

    license_expression = d.getVar("LICENSE")
    if license_expression:
        license_json = []
        licenses = license_expression.replace("|", "").replace("&", "").split()
        for license in licenses:
            converted_license = license_conversion_map.get(license, license)
            # Search for the license in COMMON_LICENSE_DIR and LICENSE_PATH
            for directory in [d.getVar("COMMON_LICENSE_DIR")] + (d.getVar("LICENSE_PATH") or "").split():
                try:
                    with (pathlib.Path(directory) / converted_license).open(errors="replace") as f:
                        license_data = {"license": {"name": converted_license}}
                        license_json.append(license_data)
                        break
                except FileNotFoundError:
                    pass
        return license_json
    return None
