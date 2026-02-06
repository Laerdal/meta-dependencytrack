# SPDX-License-Identifier: MIT
# Copyright 2022 BG Networks, Inc.

# The product name that the CVE database uses.  Defaults to BPN, but may need to
# be overriden per recipe (for example tiff.bb sets CVE_PRODUCT=libtiff).
CVE_PRODUCT ??= "${BPN}"
CVE_VERSION ??= "${PV}"
CVE_PART ??= "a"

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

python do_dependencytrack_init() {
    import uuid
    from datetime import datetime, timezone
    from json_utils import write_sbom, write_vex
    from sbom_details import get_bom_ref

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
                "bom-ref": get_bom_ref(d.getVar("MACHINE", False)),
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

    if not os.path.isfile(d.getVar("DEPENDENCYTRACK_VEX")):
        bb.debug(2, "Creating empty vex")
        write_vex(d, default_structure)
}

addhandler do_dependencytrack_init
do_dependencytrack_init[eventmask] = "bb.event.BuildStarted"

python do_dependencytrack_collect() {
    # Skip native/nativesdk/crosssdk recipes - they clear MACHINEOVERRIDES
    # which causes override-dependent variables (e.g. IMAGE_PLATFORM) to
    # resolve incorrectly, leading to SBOM path mismatches.
    classoverride = d.getVar('CLASSOVERRIDE') or ''
    if classoverride in ('class-native', 'class-nativesdk', 'class-crosssdk'):
        return

    from oe.cve_check import get_patched_cves
    from json_utils import read_json, write_json, read_sbom, read_vex, write_sbom, write_vex
    from sbom_details import get_cpe_ids, get_bom_ref, get_references, get_licenses
    from vex_handling import add_ignored_vulnerability, add_patched_vulnerability

    # load the bom
    name = d.getVar("CVE_PRODUCT")
    # filter out +gitAUTOINC from version
    version = d.getVar("CVE_VERSION").split("+git")[0]
    sbom = read_sbom(d)

    filter_suffixes = ("-native", "-dbg", "-staticdev",
                       "-doc", "-src", "-locale", "-dev")

    cve_mapping_path = d.getVar("DEPENDENCYTRACK_TMP") + "/cve_mapping.json"
    cve_mapping = read_json(cve_mapping_path) if os.path.exists(cve_mapping_path) else dict()

    def map_component_cve_name_list(recipe_name):
        return cve_mapping.get(recipe_name, [recipe_name])

    def add_component(cpe_info, temp_dependencies_json, name, version):
        bb.debug(2, f"Collecting package {name}@{version} ({cpe_info.cpe})")
        if next((c for c in sbom["components"] if c["cpe"] == cpe_info.cpe), None) is None:
            component_json = {
                "type": "application",
                "bom-ref": get_bom_ref(cpe_info.cpe),
                "name": cpe_info.product,
                "group": cpe_info.vendor,
                "version": version,
                "cpe": cpe_info.cpe,
            }

            license_json = get_licenses(d)
            if license_json:
                component_json["licenses"] = license_json

            references = get_references(d.getVar("SRC_URI").split(" "))

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
    temp_dependencies_json = read_json(dependencies_path) if os.path.exists(dependencies_path) else dict()

    part = d.getVar("CVE_PART")

    # name is set to default, so CVE_PRODUCT not set
    if name == d.getVar("BPN"):
        # there might be several packages in 1 recipe and some of them are needed to be filtered out
        for package in filter(
            lambda s: all(
                not s.endswith(suffix) for suffix in filter_suffixes
            ),
            d.getVar("PACKAGES").split()):
            # only 1 CPE product
            add_component(get_cpe_ids(package, version, part)[0], temp_dependencies_json, package, version)
    else:
        for cpe_ids in get_cpe_ids(name, version, part):
            add_component(cpe_ids, temp_dependencies_json, name, version)

    # write it back to the deployment directory
    write_sbom(d, sbom)
    write_json(dependencies_path, temp_dependencies_json)
    write_json(cve_mapping_path, cve_mapping)

    # Collecting patched and ignored CVEs
    vex = read_vex(d)
    for patched_cve_id in get_patched_cves(d):
        add_patched_vulnerability(vex, patched_cve_id)
    for cve in (d.getVarFlags("CVE_STATUS") or {}):
        from oe.cve_check import decode_cve_status
        decoded_status, _, _ = decode_cve_status(d, cve)
        if decoded_status == "Ignored":
            add_ignored_vulnerability(vex, cve)
    write_vex(d, vex)
}

addtask dependencytrack_collect before do_build after do_fetch
do_dependencytrack_collect[nostamp] = "1"
do_dependencytrack_collect[lockfiles] += "${DEPENDENCYTRACK_LOCK}"
do_rootfs[recrdeptask] += "do_dependencytrack_collect"

python do_dependencytrack_upload() {
    from sbom_details import get_bom_ref
    from json_utils import read_sbom, read_vex, read_json, write_sbom, write_vex
    from dependency_track_upload import upload_enabled, clone_project_and_wait, upload_sbom, upload_vex

    sbom_path = d.getVar("DEPENDENCYTRACK_SBOM")
    if not os.path.isfile(sbom_path):
        if upload_enabled(d, bb):
            bb.warn("dependency-track: SBOM file not found: %s" % sbom_path)
        return

    sbom = read_sbom(d)
    vex = read_vex(d)
    bb.plain("dependency-track: SBOM has %d components" % len(sbom.get("components", [])))

    install_packages_file = d.getVar("DEPENDENCYTRACK_TMP") + "/installed_packages.json"
    if not os.path.isfile(install_packages_file):
        if upload_enabled(d, bb):
            bb.warn("dependency-track: installed_packages not found: %s" % install_packages_file)
        return

    installed_pkgs = read_json(install_packages_file)
    temp_dependencies_json = read_json(d.getVar("DEPENDENCYTRACK_TMP") + "/dependencies.json")
    bb.plain("dependency-track: processing %d installed packages, %d dependency entries" % (len(installed_pkgs), len(temp_dependencies_json)))
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
                    depend = next((d for d in sbom["dependencies"] if d["ref"] == sbom_component["bom-ref"]), None)
                    if depend is None:
                        depend = {"ref": sbom_component["bom-ref"], "dependsOn": []}
                        depend["dependsOn"].append(dep_component["bom-ref"])
                        sbom["dependencies"].append(depend)
                    elif dep_component["bom-ref"] not in depend["dependsOn"]:
                        depend["dependsOn"].append(dep_component["bom-ref"])

    # Extract all ref values
    all_refs = {component["bom-ref"] for component in sbom["components"]}
    # Extract all dependsOn values
    all_depends_on = {ref for dependency in sbom["dependencies"] for ref in dependency.get("dependsOn", [])}
    # Find refs that are not in dependsOn
    refs_not_in_depends_on = list(all_refs - all_depends_on)
    # add dependencies for components that are not in dependsOn
    if refs_not_in_depends_on:
        sbom["dependencies"].append({"ref": get_bom_ref(d.getVar("MACHINE", False)), "dependsOn": refs_not_in_depends_on})

    clone_project_and_wait(d, bb)

    write_sbom(d, sbom)
    upload_sbom(d, bb)

    write_vex(d, vex)
    upload_vex(d, bb)
}

addhandler do_dependencytrack_upload
do_dependencytrack_upload[eventmask] = "bb.event.BuildCompleted"

python do_dependencytrack_installed() {
    from oe.rootfs import image_list_installed_packages
    from json_utils import write_json

    pkgs = image_list_installed_packages(d)
    write_json(d.getVar("DEPENDENCYTRACK_TMP") + "/installed_packages.json", pkgs)
}

ROOTFS_POSTUNINSTALL_COMMAND += "do_dependencytrack_installed;"
