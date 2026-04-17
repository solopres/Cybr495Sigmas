import os
import re
import stat
from concurrent.futures import ThreadPoolExecutor, as_completed
import json

# --- CONFIG ---

KEYWORDS = {
    "patient": 2,
    "dob": 3,
    "ssn": 5,
    "mrn": 4,
    "diagnosis": 2,
    "treatment": 2,
}

PATH_KEYWORDS = {
    "backup": 2,
    "export": 2,
    "dump": 3,
    "temp": 1,
    "archive": 2,
}

PATTERNS = {
    "ssn_pattern": (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), 5),
    "dob_pattern": (re.compile(r"\b\d{2}/\d{2}/\d{4}\b"), 3),
}

HIGH_RISK_THRESHOLD = 6
MEDIUM_RISK_THRESHOLD = 3


# --- PERMISSION CHECK ---

def check_permissions(path):
    issues = []
    try:
        mode = os.stat(path).st_mode

        if mode & stat.S_IROTH:
            issues.append(("world_readable", 3))
        if mode & stat.S_IWOTH:
            issues.append(("world_writable", 5))

    except Exception:
        pass

    return issues


# --- FILE ANALYSIS ---

def analyze_file(path):
    score = 0
    reasons = []

    lower_path = path.lower()

    # Path-based scoring
    for word, weight in PATH_KEYWORDS.items():
        if word in lower_path:
            score += weight
            reasons.append(word)

    # Permission scoring
    for issue, weight in check_permissions(path):
        score += weight
        reasons.append(issue)

    # Content scanning
    try:
        with open(path, "r", errors="ignore") as f:
            for line in f:
                for word, weight in KEYWORDS.items():
                    if word in line.lower():
                        score += weight
                        reasons.append(word)

                for name, (pattern, weight) in PATTERNS.items():
                    if pattern.search(line):
                        score += weight
                        reasons.append(name)

    except PermissionError:
        return None
    except Exception:
        return None

    return score, reasons


# --- CLASSIFICATION ---

def classify(score):
    if score >= HIGH_RISK_THRESHOLD:
        return "HIGH"
    elif score >= MEDIUM_RISK_THRESHOLD:
        return "MEDIUM"
    return "LOW"


# --- WORKER FUNCTION ---

def analyze_file_wrapper(path):
    result = analyze_file(path)
    if not result:
        return None

    score, reasons = result
    level = classify(score)

    if level != "LOW":
        return {
            "file": path,
            "risk": level,
            "score": score,
            "reasons": list(set(reasons))
        }

    return None


# --- FILE COLLECTION ---

def collect_files(root_dir):
    paths = []

    for root, dirs, files in os.walk(root_dir):
        # Skip problematic system dirs
        dirs[:] = [d for d in dirs if d not in ("proc", "sys", "dev")]

        for name in files:
            paths.append(os.path.join(root, name))

    return paths


# --- PARALLEL SCAN ---

def scan_parallel(root_dir, max_workers=20):
    root_dir = os.path.abspath(os.path.expanduser(root_dir))
    files = collect_files(root_dir)

    results = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(analyze_file_wrapper, f) for f in files]

        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    results.append(result)
                    print(result)

            except Exception:
                pass

    print(json.dumps(results))


# --- RUN ---

if __name__ == "__main__":
    scan_parallel("/", max_workers=10)
