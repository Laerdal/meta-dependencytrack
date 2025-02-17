# SPDX-License-Identifier: MIT
# Copyright 2022 BG Networks, Inc.

# The product name that the CVE database uses.  Defaults to BPN, but may need to
# be overriden per recipe (for example tiff.bb sets CVE_PRODUCT=libtiff).
CVE_PRODUCT ??= "${BPN}"
CVE_VERSION ??= "${PV}"
CVE_PART ??= "a"

CVE_CHECK_IGNORE ??= ""

DEPENDENCYTRACK_DIR ??= "${DEPLOY_DIR}/dependency-track/${MACHINE}"
DEPENDENCYTRACK_SBOM ??= "${DEPENDENCYTRACK_DIR}/sbom.json"
DEPENDENCYTRACK_VEX ??= "${DEPENDENCYTRACK_DIR}/vex.json"
DEPENDENCYTRACK_TMP ??= "${TMPDIR}/dependency-track/${MACHINE}"
DEPENDENCYTRACK_LOCK ??= "${DEPENDENCYTRACK_TMP}/bom.lock"

# Set DEPENDENCYTRACK_UPLOAD to False if you want to control the upload in other
# steps.
DEPENDENCYTRACK_UPLOAD ??= "False"
DEPENDENCYTRACK_PROJECT ??= ""
DEPENDENCYTRACK_API_URL ??= "http://localhost:8081/api"
DEPENDENCYTRACK_API_KEY ??= ""
DEPENDENCYTRACK_PROJECT_NAME ??= ""
DEPENDENCYTRACK_PROJECT_VERSION ??= ""
DEPENDENCYTRACK_PARENT ??= ""
DEPENDENCYTRACK_AUTO_CREATE ??= "false"

DT_LICENSE_CONVERSION_MAP ??= "{ "GPLv2+" : "GPL-2.0-or-later", "GPLv2" : "GPL-2.0", "LGPLv2" : "LGPL-2.0", "LGPLv2+" : "LGPL-2.0-or-later", "LGPLv2.1+" : "LGPL-2.1-or-later", "LGPLv2.1" : "LGPL-2.1"}"

python do_dependencytrack_init() {
    import uuid, hashlib
    from datetime import datetime, timezone

    deptrack_dir = d.getVar("DEPENDENCYTRACK_DIR")
    if not os.path.exists(deptrack_dir):
        bb.debug(2, "Creating cyclonedx directory: %s" % deptrack_dir)
        bb.utils.mkdirhier(deptrack_dir)

    default_structure = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:" + str(uuid.uuid4()),
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [
                {
                    "vendor": "Kontron AIS GmbH",
                    "name": "dependency-track",
                    "version": "1.0"
                }
            ],
            "component": {
                "type": "operating-system",
                "bom-ref": hashlib.md5(d.getVar("MACHINE", False).encode()).hexdigest(),
                "group": d.getVar("MACHINE", False),
                "name": d.getVar("DISTRO_NAME", False) + "-" + d.getVar("MACHINE").replace("kontron-", ""),
                "version": d.getVar("SECUREOS_RELEASE_VERSION", True)
            }
        },
        "components": [],
        "dependencies": [],
        "vulnerabilities": [],
    }

    if not os.path.isfile(d.getVar("DEPENDENCYTRACK_SBOM")):
        bb.debug(2, "Creating empty sbom")
        write_sbom(d, default_structure)

        # Upload minimal sbom so that the project is created and is valid for vex upload later
        upload_sbom(d)

    if not os.path.isfile(d.getVar("DEPENDENCYTRACK_VEX")):
        bb.debug(2, "Creating empty vex")
        write_vex(d, default_structure)
}

addhandler do_dependencytrack_init
do_dependencytrack_init[eventmask] = "bb.event.BuildStarted"

python do_dependencytrack_collect() {
    import json, hashlib
    from pathlib import Path
    from oe.cve_check import get_patched_cves

    # load the bom
    name = d.getVar("CVE_PRODUCT")
    # filter out +gitAUTOINC from version
    version = d.getVar("CVE_VERSION").split("+git")[0]
    sbom = read_sbom(d)

    filter_suffixes = ("-native", "-dbg", "-staticdev",
                       "-doc", "-src", "-locale", "-dev")

    cve_mapping_path = d.getVar("DEPENDENCYTRACK_TMP") + "/cve_mapping.json"
    cve_mapping = read_json(d, cve_mapping_path) if os.path.exists(
        cve_mapping_path) else dict()

    def map_component_cve_name_list(recipe_name):
        return cve_mapping.get(recipe_name, [recipe_name])

    def add_component(cpe_info, temp_dependencies_json, name, version):
        bb.debug(2, f"Collecting package {name}@{version} ({cpe_info.cpe})")
        if next((c for c in sbom["components"] if c["cpe"] == cpe_info.cpe), None) is None:
            component_json = {
                "type": "application",
                "bom-ref": cpe_info.product + " - " + hashlib.md5(cpe_info.cpe.encode()).hexdigest(),
                "name": cpe_info.product,
                "group": cpe_info.vendor,
                "version": version,
                "cpe": cpe_info.cpe,
            }

            license_json = get_licenses(d)
            if license_json:
                component_json["licenses"] = license_json

            references = get_references(d)

            if references:
                component_json["externalReferences"] = references

            sbom["components"].append(component_json)

        dependencies = d.getVar(f"RDEPENDS:{name}", True) or ""
        if dependencies.strip():
            result_list = []
            for dep in dependencies.split():
                for suffix in filter_suffixes:
                    if dep.endswith(suffix):
                        result_list.extend(
                            map_component_cve_name_list(dep[:-len(suffix)]))
                        break
                else:
                    result_list.extend(map_component_cve_name_list(dep))

            temp_dependencies_json[name] = temp_dependencies_json.get(
                name, []) + result_list

        # CVE_PRODUCT was overwritten, so mapping needs to be saved
        if d.getVar("CVE_PRODUCT") != d.getVar("BPN"):
            cve_names = [vendor_name.split(":")[-1]
                         for vendor_name in name.split()]
            cve_mapping[d.getVar("BPN")] = list(
                set(cve_mapping.get(d.getVar("BPN"), []) + cve_names))

    dependencies_path = d.getVar("DEPENDENCYTRACK_TMP") + "/dependencies.json"
    temp_dependencies_json = read_json(
        d, dependencies_path) if os.path.exists(dependencies_path) else dict()

    part = d.getVar("CVE_PART")

    # name is set to default, so CVE_PRODUCT not set
    if name == d.getVar("BPN"):
        # there might be several packages in 1 recipe and some of them are needed to be filted out
        for package in filter(
            lambda s: all(
                not s.endswith(suffix) for suffix in filter_suffixes
            ),
            d.getVar("PACKAGES").split()):
            # only 1 CPE product
            add_component(get_cpe_ids(package, version, part)[
                          0], temp_dependencies_json, package, version)
    else:
        for index, o in enumerate(get_cpe_ids(name, version, part)):
            add_component(o, temp_dependencies_json, name, version)

    # write it back to the deploy directory
    write_sbom(d, sbom)
    write_json(d, temp_dependencies_json, dependencies_path)
    write_json(d, cve_mapping, cve_mapping_path)

    # Collecting patched and ignored CVEs
    vex = read_vex(d)
    for patched_cve_id in get_patched_cves(d):
        add_patched_vulnerabitily(vex, patched_cve_id)
    for ignored_cve_id in d.getVar("CVE_CHECK_IGNORE").split():
        add_ignored_vulnerability(vex, ignored_cve_id)
    write_vex(d, vex)
}

addtask dependencytrack_collect before do_build after do_fetch
do_dependencytrack_collect[nostamp] = "1"
do_dependencytrack_collect[lockfiles] += "${DEPENDENCYTRACK_LOCK}"
do_rootfs[recrdeptask] += "do_dependencytrack_collect"

python do_dependencytrack_upload() {
    import json, base64, hashlib, requests
    from pathlib import Path

    sbom = read_sbom(d)
    vex = read_vex(d)

    installed_pkgs = read_json(d, d.getVar(
        "DEPENDENCYTRACK_TMP") + "/installed_packages.json")
    pkgs_names = list(installed_pkgs.keys())

    temp_dependencies_json = read_json(d, d.getVar(
        "DEPENDENCYTRACK_TMP") + "/dependencies.json")
    for package, dependencies in temp_dependencies_json.items():
        if not installed_pkgs.get(package, None):
            installed_pkgs[package] = {"deps": dependencies}
        else:
            installed_pkgs[package]["deps"].extend(dependencies)

    components_dict = {component["name"]: component for component in sbom["components"]}
    for sbom_component in sbom["components"]:
        pkg = installed_pkgs.get(sbom_component["name"])

        if pkg:
            for dep in pkg.get("deps", []):
                dep_component = components_dict.get(dep)
                if dep_component and dep_component["bom-ref"] != sbom_component["bom-ref"]:
                    depend = next(
                        (d for d in sbom["dependencies"] if d["ref"] == sbom_component["bom-ref"]), None)
                    if depend is None:
                        depend = {
                            "ref": sbom_component["bom-ref"], "dependsOn": []}
                        depend["dependsOn"].append(dep_component["bom-ref"])
                        sbom["dependencies"].append(depend)
                    elif dep_component["bom-ref"] not in depend["dependsOn"]:
                        depend["dependsOn"].append(dep_component["bom-ref"])

    # Extract all ref values
    all_refs = {component["bom-ref"] for component in sbom["components"]}
    # Extract all dependsOn values
    all_depends_on = {
        ref for dependency in sbom["dependencies"] for ref in dependency.get("dependsOn", [])}
    # Find refs that are not in dependsOn
    refs_not_in_depends_on = all_refs - all_depends_on
    # add dependencies for components that are not in dependsOn
    sbom["dependencies"].append({"ref": hashlib.md5(d.getVar(
        "MACHINE", False).encode()).hexdigest(), "dependsOn": list(refs_not_in_depends_on)})

    write_sbom(d, sbom)
    upload_sbom(d)

    write_vex(d, vex)
    upload_vex(d)
}

python do_dependencytrack_installed() {
    from oe.rootfs import image_list_installed_packages
    pkgs = image_list_installed_packages(d)
    write_json(d, pkgs, d.getVar("DEPENDENCYTRACK_TMP") +
               "/installed_packages.json")
}

ROOTFS_POSTUNINSTALL_COMMAND += "do_dependencytrack_installed;"

addhandler do_dependencytrack_upload
do_dependencytrack_upload[eventmask] = "bb.event.BuildCompleted"


def read_sbom(d):
    return read_json(d, d.getVar("DEPENDENCYTRACK_SBOM"))


def read_vex(d):
    return read_json(d, d.getVar("DEPENDENCYTRACK_VEX"))


def read_json(d, path):
    import json
    from pathlib import Path
    return json.loads(Path(path).read_text())


def write_sbom(d, sbom):
    write_json(d, sbom, d.getVar("DEPENDENCYTRACK_SBOM"))


def write_vex(d, vex):
    write_json(d, vex, d.getVar("DEPENDENCYTRACK_VEX"))


def write_json(d, data, path):
    import json
    from pathlib import Path
    Path(path).write_text(json.dumps(data, indent=2))


def get_references(d):
    import re
    pattern = re.compile(
        r"http[s]*:\/\/[a-z.]*\/[a-z.\-\/]*[a-z.\-].(tar.([gxl]?z|bz2)|tgz)")
    src_uris = d.getVar("SRC_URI").split(" ")
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
    import json
    from pathlib import Path
    license_expression = d.getVar("LICENSE")
    if license_expression:
        license_json = []
        license_conversion_map = json.loads(
            d.getVar("DT_LICENSE_CONVERSION_MAP"))
        licenses = license_expression.replace("|", "").replace("&", "").split()
        for license in licenses:
            if license in license_conversion_map:
                converted_license = license_conversion_map[license]
            else:
                converted_license = license
            # Search for the license in COMMON_LICENSE_DIR and LICENSE_PATH
            for directory in [d.getVar("COMMON_LICENSE_DIR")] + (d.getVar("LICENSE_PATH") or "").split():
                try:
                    with (Path(directory) / converted_license).open(errors="replace") as f:
                        license_data = {"license": {"name": converted_license}}
                        license_json.append(license_data)
                        break
                except FileNotFoundError:
                    pass
        return license_json
    return None


def get_cpe_ids(cve_product, version, part):
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


def add_patched_vulnerabitily(vex, cve_id):
    vulnerability = next(
        (v for v in vex["vulnerabilities"] if v["id"] == cve_id), None)
    if vulnerability is None:
        add_vulnerability(vex, cve_id, "resolved", "update",
                          "CVE_CHECK data : The vulnerability has been Patched!")
    else:  # (write to patched, even if already ignored)
        vulnerability["analysis"].update({"state": "resolved", "response": [
                                         "update"], "detail": "CVE_CHECK data: The vulnerability has been Patched!"})


def add_ignored_vulnerability(vex, cve_id):
    if next((v for v in vex["vulnerabilities"] if v["id"] == cve_id), None) is None:
        add_vulnerability(vex, cve_id, "resolved", "will_not_fix",
                          "CVE_CHECK data : The vulnerability has been Ignored!")


def add_vulnerability(vex, cve_id, analysis_state, analysis_response, analysis_detail):
    vex["vulnerabilities"].append({
        "id": cve_id,
        "source": {"name": "NVD", "url": "https://nvd.nist.gov/"},
        "analysis": {"state": analysis_state, "response": [analysis_response], "detail": analysis_detail},
        "affects": [{"ref": vex["metadata"]["component"]["bom-ref"]}]
    })


def upload_sbom(d):
    dt_upload = bb.utils.to_boolean(d.getVar("DEPENDENCYTRACK_UPLOAD"))
    if not dt_upload:
        return

    dt_url = d.getVar("DEPENDENCYTRACK_API_URL") + "/v1/bom"
    dt_parent = d.getVar("DEPENDENCYTRACK_PARENT")
    dt_project = d.getVar("DEPENDENCYTRACK_PROJECT")
    dt_auto_create = d.getVar("DEPENDENCYTRACK_AUTO_CREATE")
    dt_project_name = d.getVar("DEPENDENCYTRACK_PROJECT_NAME")
    dt_project_version = d.getVar("DEPENDENCYTRACK_PROJECT_VERSION")
    files = {
        "parentUUID": dt_parent,
        "autoCreate": dt_auto_create,
        "bom": open(d.getVar("DEPENDENCYTRACK_SBOM"), 'rb')
    }

    if dt_project == "":
        files["projectName"] = dt_project_name
        files["projectVersion"] = dt_project_version
    else:
        files["project"] = dt_project

    post_request(dt_url, files)


def upload_vex(d):
    dt_upload = bb.utils.to_boolean(d.getVar("DEPENDENCYTRACK_UPLOAD"))
    if not dt_upload:
        return

    dt_url = d.getVar('DEPENDENCYTRACK_API_URL') + "/v1/vex"
    dt_project = d.getVar("DEPENDENCYTRACK_PROJECT")
    dt_project_name = d.getVar("DEPENDENCYTRACK_PROJECT_NAME")
    dt_project_version = d.getVar("DEPENDENCYTRACK_PROJECT_VERSION")
    files = {"vex": open(d.getVar("DEPENDENCYTRACK_VEX"), "rb")}

    if dt_project == "":
        files["projectName"] = dt_project_name
        files["projectVersion"] = dt_project_version
    else:
        files["project"] = dt_project

    post_request(dt_url, files)


def post_request(url, files):
    import requests
    headers = {"X-API-Key": d.getVar("DEPENDENCYTRACK_API_KEY")}

    try:
        response = requests.post(url, headers=headers, files=files)
        response.raise_for_status()
    except requests.exceptions.HTTPError as e:
        bb.error(
            f"Failed to upload to Dependency Track server at {url}. [HTTP Error] {e}")
        bb.error(f"Response: {response.status_code} -> {response.reason}")
    except requests.exceptions.RequestException as e:
        bb.error(
            f"Failed to upload to Dependency Track server at {url}. [Error] {e}")
    else:
        bb.debug(2, f"File successfully uploaded to {url}")
