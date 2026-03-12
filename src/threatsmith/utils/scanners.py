import shutil


def detect_scanners() -> dict[str, list[str]]:
    """
    Detect available security scanners on the system using shutil.which().

    Returns:
        dict: {'available': [...], 'unavailable': [...]} scanner names
    """
    scanners = ["semgrep", "trivy", "gitleaks"]
    available = []
    unavailable = []

    for scanner in scanners:
        if shutil.which(scanner):
            available.append(scanner)
        else:
            unavailable.append(scanner)

    return {
        "available": available,
        "unavailable": unavailable,
    }
