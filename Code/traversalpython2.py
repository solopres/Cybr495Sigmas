import os
import re
import stat
import json

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


def check_permissions(path):
    issues = []
    try:
        mode = os.stat(path).st_mode
        if mode & stat.S_IROTH:
            issues.append(("world_readable", 3))
        if mode & stat.S_IWOTH:
            issues.append(("world_writable", 5))
    except:
        pass
    return issues


def analyze_file(path):
    score = 0
    reasons = []
    lower_path = path.lower()

    for word, weight in PATH_KEYWORDS.items():
        if word in lower_path:
            score += weight
            reasons.append(word)

    for issue, weight in check_permissions(path):
        score += weight
        reasons.append(issue)

    try:
        f = open(path, "r")
        for line in f:
            lower_line = line.lower()

            for word, weight in KEYWORDS.items():
                if word in lower_line:
                    score += weight
                    reasons.append(word)

            for name, (pattern, weight) in PATTERNS.items():
                if pattern.search(line):
                    score += weight
                    reasons.append(name)
        f.close()
    except:
        return None

    return score, reasons


def classify(score):
    if score >= HIGH_RISK_THRESHOLD:
        return "HIGH"
    elif score >= MEDIUM_RISK_THRESHOLD:
        return "MEDIUM"
    return "LOW"


def collect_files(root_dir):
    paths = []
    for root, dirs, files in os.walk(root_dir):
        dirs[:] = [d for d in dirs if d not in ("proc", "sys", "dev")]
        for name in files:
            paths.append(os.path.join(root, name))
    return paths


def scan(root_dir):
    root_dir = os.path.abspath(os.path.expanduser(root_dir))
    files = collect_files(root_dir)
    results = []

    for path in files:
        result = analyze_file(path)
        if not result:
            continue

        score, reasons = result
        level = classify(score)

        if level != "LOW":
            item = {
                "file": path,
                "risk": level,
                "score": score,
                "reasons": list(set(reasons))
            }
            results.append(item)
            print(item)

    print(json.dumps(results))


if __name__ == "__main__":
    scan("/home")