"""Converts Chainguard osquery SQL to FleetDM YAML from a osquery-defense-kit repo"""

from copy import deepcopy
from datetime import datetime
from pathlib import Path
from sys import exit as sysexit
import re
import yaml

# pylint: disable=invalid-name
# pylint: disable=line-too-long

OSQUERY_KIT_PATH = r".*\/(security-)?osquery-defense-kit(.git)?"
OSQUERY_VER = r"(\d\.\d{1,2}\.\d)"
OSQUERY_VER_STR = rf"(.*?)(osquery v){OSQUERY_VER}(.*?)"
CHAINGUARD_SQLS = [  # Can add "policies" later if desired
    {"dir": "detection", "yml": "chainguard-detection-queries.yml"},
    {"dir": "incident_response", "yml": "chainguard-ir-queries.yml"},
]
CHAINGUARD_META_STRS = (
    [  # Common chainguard sql comments that have metadata for FleetDM
        {"metaType": "tags", "match": "-- tags: "},
        {"metaType": "interval", "match": "-- interval: "},
        {"metaType": "platforms", "match": "-- platform: "},
    ]
)
FLEET_FORMAT = {
    "apiVersion": "v1",
    "kind": "query",
    "spec": {
        "automations_enabled": False,
        "description": "",
        "discard_data": False,
        "interval": "0",
        "logging": "snapshot",
        "min_osquery_version": "",
        "name": "",
        "platforms": "",
        # "purpose": "", --Why did I add this earlier?
        "observer_can_run": False,
        "query": "",
        "tags": "",
        "team": "",
    },
}


def str_presenter(dumper, data):
    """Configures yaml for dumping multiline strings to ensure pretty fleetdm yaml from the SQL format
    https://stackoverflow.com/questions/8640959/how-can-i-control-what-scalar-form-pyyaml-uses-for-my-data
    Args:
        `dumper`: an instance of the `yaml.Dumper` class, which is used to dump the data to YAML format.
        `data`: the data to be dumped, which is a multiline string."""
    if data.count("\n") > 0:
        block = "\n".join([line.rstrip() for line in data.splitlines()])
        if data.endswith("\n"):
            block += "\n"
        return dumper.represent_scalar("tag:yaml.org,2002:str", block, style="|")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


def setOsqueryMinVersion() -> bool:
    """Pulls the minimum OSQuery version from chainguard's README.md and sets it in the
    FLEET_FORMAT constant.
    Returns:
        bool: False if it couldn't be found in the README."""
    with open("README.md", "r", encoding="utf-8") as readme:
        for l in readme.readlines():
            match = re.search(OSQUERY_VER_STR, l)
            if match and re.match(OSQUERY_VER, match.group(3)):
                print(
                    f"Info: Found and set minimum osquery version ({match.group(3)}) from README.md"
                )
                FLEET_FORMAT["spec"]["min_osquery_version"] = match.group(3)
                return True
    return False


def setFleetMetadata(q: str, filename: str) -> dict:
    """Reads the metadata from a chainguard SQL query (tags, platforms, interval),
    parses, and adds to the corresponding key in the FleetDM-formatted dictionary
     Args:
        q (str): The chainguard SQL query.
        filename (str): The name of the file that contains the query.
    Returns:
        dict: A FleetDM-formatted dictionary with the metadata added."""
    p = deepcopy(FLEET_FORMAT)
    p["spec"]["query"] = q
    # Description is always the first line of the SQL
    # Some descriptions that are too long get newline'd in the output to disk
    # dunno how to fix that yet but it's still valid yaml
    p["spec"]["description"] = q.partition("\n")[0].lstrip("-- ")
    # Output like "chainguard - {pack or detection type name} - {query name}"
    name = str(Path(filename).relative_to(Path.cwd())).removesuffix(r".sql").split("/")
    p["spec"]["name"] = f"chainguard - {name[len(name)-2]} - {name[len(name)-1]}"

    for l in q.splitlines():  # For every line in the original SQL
        # Always expect the SELECT to come after the comment section of queries, so bail.
        if l.startswith("SELECT"):
            break
        for j in CHAINGUARD_META_STRS:  # Check each special metadata string
            match = re.search(rf"({j['match']})(.*)", l)  # two capturing groups
            if match:  # Found a special metadata  line in query
                if j["metaType"] == "interval" and match.group(2).isdigit():
                    p["spec"][f"{j['metaType']}"] = int(match.group(2))
                elif j["metaType"] in ("tags", "platforms"):
                    p["spec"][f"{j['metaType']}"] = ", ".join(match.group(2).split(" "))
    return p


# def readPrepYaml(p: dict[str, str]) -> list[dict]:
def readPrepYaml(p: str) -> list[dict]:
    """Reads all .sql files in the directory, prepares them in a FleetDM-formatted dict,
    and returns as a list of dictionaries.
    Args:
        p (str): The directory to scrap for SQL files
    Returns:
        list (dict): A list of a FleetDM-formatted dictionaries"""
    fleet_pack = []
    for file in sorted(Path(f"{Path.cwd()}/{p}").rglob("*.sql")):
        # print(f"Info: Reading query from {file}")
        query = Path(file).read_text(encoding="utf-8")
        if query:
            fleet_pack.append(setFleetMetadata(query, str(file)))
    return fleet_pack


def writeTemplate(name: str, p: list[dict]):
    """Writes the FleetDM-formatted dictionary to its corresponding YAML files.
    Args:
        name (str): The filename to write to
        list (dict): A list of a FleetDM-formatted dictionaries"""
    query_dict = (
        f"{Path.cwd()}/fleetdm_output/{datetime.today().strftime('%Y%m%d')}_{name}"
    )
    yaml.add_representer(str, str_presenter)
    with open(query_dict, "w", encoding="utf-8") as out:
        yaml.dump_all(p, out, indent=2)


if __name__ == "__main__":
    ERROR_MSG = ""
    if re.match(OSQUERY_KIT_PATH, str(Path.cwd())):
        if all(Path(i["dir"]).exists() for i in CHAINGUARD_SQLS):
            if setOsqueryMinVersion():
                try:
                    for i in CHAINGUARD_SQLS:
                        print(f"Info: Reading queries from {i['dir']}")
                        pack = readPrepYaml(i["dir"])
                        if pack:
                            print(f"Info: Writing prepared queries {i['yml']}")
                            writeTemplate(i["yml"], pack)
                        else:
                            ERROR_MSG = f"Error: Couldn't read SQL or write YAML to disk for {i['dir']}"
                # pylint: disable=broad-exception-caught
                except Exception as e:  # Probably just File I/O and permissions stuff
                    ERROR_MSG = f"Error: I didn't prepare for this so you figure it out: {str(e)}"
            else:
                ERROR_MSG = "Error: Unable to find and set minimum osquery version from README.md"

        else:
            ERROR_MSG = "Error: Directory missing one or more of the following directories:\n\t{}\n".format(
                "\n\t".join(i["dir"] for i in CHAINGUARD_SQLS)
            )
    else:
        ERROR_MSG = f"Error: Script needs to run from a {OSQUERY_KIT_PATH} path"
    print(ERROR_MSG)
    sysexit(1)
