import requests
import time
from dependency_track_requests import post_request, put_request, get_request
from urllib.parse import quote


def clone_project_and_wait(d, bb) -> None:
    if project_exists(d, bb):
        # no error, nothing to do
        return

    latest_uuid = get_projects_latest_version(d, bb)
    if not latest_uuid:
        # error was logged in get_projects_latest_version
        return

    response = clone_project(d, bb, latest_uuid)
    if not response:
        # error was logged in clone_project or no upload needed
        return

    try:
        clone_task_id = response.json()["token"]
    except (ValueError, KeyError):
        bb.error(f"Failed to parse clone response {response}")
        return
    else:
        while not task_finished(d, bb, clone_task_id):
            bb.debug(2, "Waiting for project clone to finish...")
            time.sleep(10)


def project_exists(d, bb) -> bool:
    if d.getVar("DEPENDENCYTRACK_PROJECT") != "":
        # if project's UUID is set then the project exists
        return True

    dt_url = d.getVar("DEPENDENCYTRACK_API_URL") + "/v1/project/lookup"

    # API return 200 and json project info if project exists and 404 if it doesn't
    response = get_request(bb, dt_url, d.getVar("DEPENDENCYTRACK_API_KEY"), params={
        "name": d.getVar("DEPENDENCYTRACK_PROJECT_NAME"),
        "version": d.getVar("DEPENDENCYTRACK_PROJECT_VERSION")
    })
    if not response:
        # error was logged in get_request
        return False

    if response.status_code == 200:
        # project was returned
        return True
    elif response.status_code == 404:
        # 404 was returned, expected output for non-existent project
        return False
    else:
        bb.error(f"Failed to check if project exists: {response}")

    return False


def get_projects_latest_version(d, bb) -> str | None:
    if d.getVar("DEPENDENCYTRACK_PROJECT") != "":
        # if project's UUID is set, version is irrelevant
        return None

    dt_url = d.getVar(
        "DEPENDENCYTRACK_API_URL") + f"/v1/project/latest/{quote(d.getVar('DEPENDENCYTRACK_PROJECT_NAME'))}"

    # API returns json with project info which contains {"uuid": str} among other things not used here
    response = get_request(bb, dt_url, d.getVar("DEPENDENCYTRACK_API_KEY"), params={})
    if not response:
        # error was logged in get_request
        return None

    try:
        latest_uuid = response.json()["uuid"]
    except (ValueError, KeyError):
        bb.error(f"Failed to parse project response when getting latest version {response}")
        return None

    return latest_uuid


def clone_project(d, bb, uuid: str) -> requests.Response | None:
    dt_upload = bb.utils.to_boolean(d.getVar("DEPENDENCYTRACK_UPLOAD"))
    if not dt_upload:
        return None

    dt_url = d.getVar("DEPENDENCYTRACK_API_URL") + "/v1/project/clone"

    # API returns {"token": str}
    return put_request(bb, dt_url, d.getVar("DEPENDENCYTRACK_API_KEY"),
                       json={"project": uuid, "version": d.getVar("DEPENDENCYTRACK_PROJECT_VERSION"),
                             "includeACL": True,
                             "includeAuditHistory": True,
                             "includeComponents": True,
                             "includeDependencies": True,
                             "includePolicyViolations": True,
                             "includeProperties": True,
                             "includeServices": True,
                             "includeTags": True,
                             "makeCloneLatest": True})


def task_finished(d, bb, task_id: str) -> bool:
    dt_url = d.getVar("DEPENDENCYTRACK_API_URL") + f"/v1/event/token/{task_id}"

    # API returns {"processing": bool}
    response = get_request(bb, dt_url, d.getVar("DEPENDENCYTRACK_API_KEY"), params={})
    if not response:
        # error was logged in get_request
        return True

    try:
        return not response.json()["processing"]
    except (ValueError, KeyError):
        bb.error(f"Failed to parse task ({task_id}) response, {response}")

    return True


def upload_sbom(d, bb) -> None:
    dt_upload = bb.utils.to_boolean(d.getVar("DEPENDENCYTRACK_UPLOAD"))
    if not dt_upload:
        return

    dt_url = d.getVar("DEPENDENCYTRACK_API_URL") + "/v1/bom"
    dt_parent = d.getVar("DEPENDENCYTRACK_PARENT")
    dt_project = d.getVar("DEPENDENCYTRACK_PROJECT")
    dt_auto_create = d.getVar("DEPENDENCYTRACK_AUTO_CREATE")
    dt_project_name = d.getVar("DEPENDENCYTRACK_PROJECT_NAME")
    dt_project_version = d.getVar("DEPENDENCYTRACK_PROJECT_VERSION")
    with open(d.getVar("DEPENDENCYTRACK_SBOM"), 'rb') as sbom_file:
        files = {
            "parentUUID": dt_parent,
            "autoCreate": dt_auto_create,
            "bom": sbom_file.read()
        }

    if dt_project == "":
        files["projectName"] = dt_project_name
        files["projectVersion"] = dt_project_version
    else:
        files["project"] = dt_project

    post_request(bb, dt_url, d.getVar("DEPENDENCYTRACK_API_KEY"), files=files)


def upload_vex(d, bb) -> None:
    dt_upload = bb.utils.to_boolean(d.getVar("DEPENDENCYTRACK_UPLOAD"))
    if not dt_upload:
        return

    dt_url = d.getVar("DEPENDENCYTRACK_API_URL") + "/v1/vex"
    dt_project = d.getVar("DEPENDENCYTRACK_PROJECT")
    dt_project_name = d.getVar("DEPENDENCYTRACK_PROJECT_NAME")
    dt_project_version = d.getVar("DEPENDENCYTRACK_PROJECT_VERSION")
    with open(d.getVar("DEPENDENCYTRACK_VEX"), "rb") as vex_file:
        files = {"vex": vex_file.read()}

    if dt_project == "":
        files["projectName"] = dt_project_name
        files["projectVersion"] = dt_project_version
    else:
        files["project"] = dt_project

    post_request(bb, dt_url, d.getVar("DEPENDENCYTRACK_API_KEY"), files=files)
