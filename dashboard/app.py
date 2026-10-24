from flask import Flask, render_template
import os
import requests
import zipfile
import io
import json
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_OWNER = os.getenv("GITHUB_OWNER")
GITHUB_REPO = os.getenv("GITHUB_REPO")

GITHUB_API = "https://api.github.com"


def github_headers():
    return {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "X-GitHub-Api-Version": "2022-11-28"
    }


# ---------------------------------------------------------
# Workflow configurations
# ---------------------------------------------------------

WORKFLOWS = {
    "C0": {
        "name": "C0 Baseline CI/CD",
        "artifact": "C0-Baseline-Measurement",
        "json_file": "c0_results.json"
    },

    "C1": {
        "name": "C1 SAST CI/CD",
        "artifact": "C1-SAST-Measurement",
        "json_file": "c1_results.json"
    },

    "C2": {
        "name": "C2 Gitleaks CI/CD",
        "artifact": "C2-Security-Measurement",
        "json_file": "c2_results.json"
    },

     "C3": {
        "name": "C3 Dependency CI/CD",
        "artifact": "C3-Dependency-Measurement",
        "json_file": "c3_results.json"
    },
     
     "C4": {
        "name": "C4 Trivy CI/CD",
        "artifact": "C4-Trivy-Measurement",
        "json_file": "c4_results.json"
    }
}


# ---------------------------------------------------------
# Get GitHub workflow runs
# ---------------------------------------------------------

def get_workflow_runs():

    url = (
        f"{GITHUB_API}/repos/"
        f"{GITHUB_OWNER}/{GITHUB_REPO}/actions/runs"
    )

    params = {
        "per_page": 100
    }

    response = requests.get(
        url,
        headers=github_headers(),
        params=params,
        timeout=30
    )

    response.raise_for_status()

    return response.json().get("workflow_runs", [])


# ---------------------------------------------------------
# Get measurement artifact from a workflow run
# ---------------------------------------------------------

def get_measurement(run_id, artifact_name, json_file):

    url = (
        f"{GITHUB_API}/repos/"
        f"{GITHUB_OWNER}/{GITHUB_REPO}"
        f"/actions/runs/{run_id}/artifacts"
    )

    response = requests.get(
        url,
        headers=github_headers(),
        timeout=30
    )

    response.raise_for_status()

    artifacts = response.json().get("artifacts", [])

    measurement_artifact = None

    for artifact in artifacts:

        if artifact.get("name") == artifact_name:
            measurement_artifact = artifact
            break

    if not measurement_artifact:
        return None

    download_url = measurement_artifact["archive_download_url"]

    response = requests.get(
        download_url,
        headers=github_headers(),
        timeout=30
    )

    response.raise_for_status()

    with zipfile.ZipFile(
        io.BytesIO(response.content)
    ) as zip_file:

        if json_file not in zip_file.namelist():
            return None

        with zip_file.open(json_file) as file:

            return json.load(file)


# ---------------------------------------------------------
# Dashboard
# ---------------------------------------------------------

@app.route("/")
def dashboard():

    try:

        all_runs = get_workflow_runs()

        dashboard_runs = []

        for run in all_runs:

            workflow_name = run.get("name")

            configuration = None

            for config, workflow in WORKFLOWS.items():

                if workflow["name"] == workflow_name:
                    configuration = config
                    break

            # Ignore workflows other than C0, C1 and C2
            if configuration is None:
                continue

            workflow_info = WORKFLOWS[configuration]

            measurement = None

            try:

                measurement = get_measurement(
                    run["id"],
                    workflow_info["artifact"],
                    workflow_info["json_file"]
                )

            except Exception:

                measurement = None

            dashboard_runs.append({
                "run_number": run["run_number"],
                "configuration": configuration,
                "workflow_name": workflow_name,
                "status": run["status"],
                "conclusion": run["conclusion"],
                "date": run["created_at"],
                "measurement": measurement
            })

        # Sort newest runs first
        dashboard_runs.sort(
            key=lambda x: x["date"],
            reverse=True
        )

        return render_template(
            "dashboard.html",
            runs=dashboard_runs,
            error=None
        )

    except Exception as e:

        return render_template(
            "dashboard.html",
            runs=[],
            error=str(e)
        )


# ---------------------------------------------------------
# Run Flask application
# ---------------------------------------------------------

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5001,
        debug=True
    )