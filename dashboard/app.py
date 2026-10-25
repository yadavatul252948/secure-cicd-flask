from flask import Flask, render_template
import os
import requests
import zipfile
import io
import json
import time
from dotenv import load_dotenv

# ============================================================
# Load environment variables
# ============================================================

load_dotenv()

app = Flask(__name__)

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_OWNER = os.getenv("GITHUB_OWNER")
GITHUB_REPO = os.getenv("GITHUB_REPO")

GITHUB_API = "https://api.github.com"

# ============================================================
# Dashboard settings
# ============================================================

# Show only the latest 5 runs for each configuration
RECENT_RUNS = 5

# Cache GitHub data for 30 seconds
CACHE_TTL = 30


# ============================================================
# Workflow configuration
# ============================================================

WORKFLOWS = {
    "C0": {
        "name": "C0 Baseline CI/CD",
        "file": "baseline.yml",
        "artifact": "C0-Baseline-Measurement",
        "json_file": "c0_results.json"
    },

    "C1": {
        "name": "C1 SAST CI/CD",
        "file": "c1-sast.yml",
        "artifact": "C1-SAST-Measurement",
        "json_file": "c1_results.json"
    },

    "C2": {
        "name": "C2 Gitleaks CI/CD",
        "file": "c2-gitleaks.yml",
        "artifact": "C2-Security-Measurement",
        "json_file": "c2_results.json"
    },

    "C3": {
        "name": "C3 Dependency CI/CD",
        "file": "c3-dependency.yml",
        "artifact": "C3-Dependency-Measurement",
        "json_file": "c3_results.json"
    },

    "C4": {
        "name": "C4 Trivy CI/CD",
        "file": "c4-trivy.yml",
        "artifact": "C4-Trivy-Measurement",
        "json_file": "c4_results.json"
    }
}


# ============================================================
# In-memory cache
# ============================================================

CACHE = {
    "timestamp": 0,
    "runs": None,
    "error": None
}


# ============================================================
# GitHub API headers
# ============================================================

def github_headers():
    return {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "X-GitHub-Api-Version": "2022-11-28"
    }


# ============================================================
# Get latest runs for a specific workflow
# ============================================================

def get_workflow_runs(workflow_file):

    url = (
        f"{GITHUB_API}/repos/"
        f"{GITHUB_OWNER}/{GITHUB_REPO}/"
        f"actions/workflows/{workflow_file}/runs"
    )

    params = {
        "per_page": RECENT_RUNS,
        "page": 1
    }

    response = requests.get(
        url,
        headers=github_headers(),
        params=params,
        timeout=15
    )

    response.raise_for_status()

    data = response.json()

    return data.get("workflow_runs", [])


# ============================================================
# Get repository artifacts
# ============================================================

def get_all_artifacts():

    url = (
        f"{GITHUB_API}/repos/"
        f"{GITHUB_OWNER}/{GITHUB_REPO}/"
        f"actions/artifacts"
    )

    params = {
        "per_page": 100,
        "page": 1
    }

    response = requests.get(
        url,
        headers=github_headers(),
        params=params,
        timeout=15
    )

    response.raise_for_status()

    data = response.json()

    return data.get("artifacts", [])


# ============================================================
# Find the correct measurement artifact
# ============================================================

def find_measurement_artifact(
    artifacts,
    run_id,
    artifact_name
):

    for artifact in artifacts:

        if artifact.get("name") != artifact_name:
            continue

        workflow_run = artifact.get("workflow_run")

        if workflow_run:

            artifact_run_id = workflow_run.get("id")

            if artifact_run_id == run_id:
                return artifact

    return None


# ============================================================
# Download artifact and read JSON measurement
# ============================================================

def get_measurement(
    artifact,
    json_file
):

    if not artifact:
        return None

    artifact_id = artifact.get("id")

    if not artifact_id:
        return None

    url = (
        f"{GITHUB_API}/repos/"
        f"{GITHUB_OWNER}/{GITHUB_REPO}/"
        f"actions/artifacts/{artifact_id}/zip"
    )

    response = requests.get(
        url,
        headers=github_headers(),
        timeout=30
    )

    response.raise_for_status()

    zip_data = io.BytesIO(response.content)

    with zipfile.ZipFile(zip_data) as z:

        if json_file not in z.namelist():
            return None

        with z.open(json_file) as file:
            return json.load(file)


# ============================================================
# Load dashboard data
# ============================================================

def load_dashboard_data():

    global CACHE

    current_time = time.time()

    # --------------------------------------------------------
    # Use cache if it is still valid
    # --------------------------------------------------------

    if (
        CACHE["runs"] is not None
        and current_time - CACHE["timestamp"] < CACHE_TTL
    ):

        return CACHE["runs"], CACHE["error"]


    runs = []
    error = None


    try:

        # ----------------------------------------------------
        # Validate environment variables
        # ----------------------------------------------------

        if not GITHUB_TOKEN:
            raise Exception(
                "GITHUB_TOKEN is missing from the .env file."
            )

        if not GITHUB_OWNER:
            raise Exception(
                "GITHUB_OWNER is missing from the .env file."
            )

        if not GITHUB_REPO:
            raise Exception(
                "GITHUB_REPO is missing from the .env file."
            )


        # ----------------------------------------------------
        # Get repository artifacts only once
        # ----------------------------------------------------

        artifacts = get_all_artifacts()


        # ----------------------------------------------------
        # Get latest 5 runs for each configuration
        # ----------------------------------------------------

        for configuration, workflow in WORKFLOWS.items():

            workflow_runs = get_workflow_runs(
                workflow["file"]
            )

            # Keep only latest 5
            workflow_runs = workflow_runs[:RECENT_RUNS]


            # ------------------------------------------------
            # Process selected runs
            # ------------------------------------------------

            for workflow_run in workflow_runs:

                run_id = workflow_run.get("id")

                artifact = find_measurement_artifact(
                    artifacts,
                    run_id,
                    workflow["artifact"]
                )

                measurement = None


                # ------------------------------------------------
                # Download measurement only if artifact exists
                # ------------------------------------------------

                if artifact:

                    try:

                        measurement = get_measurement(
                            artifact,
                            workflow["json_file"]
                        )

                    except Exception as artifact_error:

                        print(
                            f"Measurement error for "
                            f"{configuration} "
                            f"run #{workflow_run.get('run_number')}: "
                            f"{artifact_error}"
                        )


                # ------------------------------------------------
                # Add run information
                # ------------------------------------------------

                runs.append({
                    "run_number": workflow_run.get(
                        "run_number"
                    ),

                    "configuration": configuration,

                    "workflow_name": workflow["name"],

                    "status": workflow_run.get(
                        "status"
                    ),

                    "conclusion": workflow_run.get(
                        "conclusion"
                    ),

                    "created_at": workflow_run.get(
                        "created_at"
                    ),

                    "updated_at": workflow_run.get(
                        "updated_at"
                    ),

                    "run_id": run_id,

                    "measurement": measurement
                })


        # ----------------------------------------------------
        # Sort newest runs first
        # ----------------------------------------------------

        runs.sort(
            key=lambda x: x.get("created_at") or "",
            reverse=True
        )


        # ----------------------------------------------------
        # Update cache
        # ----------------------------------------------------

        CACHE["timestamp"] = current_time
        CACHE["runs"] = runs
        CACHE["error"] = None

        return runs, None


    except requests.exceptions.RequestException as e:

        error = f"GitHub API error: {e}"

    except Exception as e:

        error = str(e)


    # --------------------------------------------------------
    # Store error in cache
    # --------------------------------------------------------

    CACHE["timestamp"] = current_time
    CACHE["runs"] = []
    CACHE["error"] = error

    return [], error


# ============================================================
# Dashboard route
# ============================================================

@app.route("/")
def dashboard():

    runs, error = load_dashboard_data()

    return render_template(
        "dashboard.html",
        runs=runs,
        error=error
    )


# ============================================================
# Start Flask application
# ============================================================

if __name__ == "__main__":

    print()
    print("==============================================")
    print(" CI/CD Security & Performance Dashboard")
    print("==============================================")
    print()
    print("Showing latest 5 runs for each:")
    print("  C0 - Baseline")
    print("  C1 - SAST")
    print("  C2 - Gitleaks")
    print("  C3 - Dependency")
    print("  C4 - Trivy")
    print()
    print("Maximum measurements displayed: 25")
    print()
    print("Dashboard URL:")
    print("http://127.0.0.1:5001")
    print()
    print("Cache duration: 30 seconds")
    print("==============================================")
    print()

    app.run(
        host="127.0.0.1",
        port=5001,
        debug=True
    )