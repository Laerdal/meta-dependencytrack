import json
import pathlib


def read_json(path: str) -> dict:
    return json.loads(pathlib.Path(path).read_text())


def write_json(path: str, data: dict) -> None:
    pathlib.Path(path).write_text(json.dumps(data, indent=2))


def read_sbom(d):
    return read_json(d.getVar("DEPENDENCYTRACK_SBOM"))


def write_sbom(d, sbom):
    write_json(d.getVar("DEPENDENCYTRACK_SBOM"), sbom)


def read_vex(d):
    return read_json(d.getVar("DEPENDENCYTRACK_VEX"))


def write_vex(d, vex):
    write_json(d.getVar("DEPENDENCYTRACK_VEX"), vex)
