"""Network diagnostics for the admin page."""

import subprocess


def ping(host: str) -> str:
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)
    return result.stdout


def traceroute(host: str) -> str:
    result = subprocess.run(["traceroute", "--", host], capture_output=True, text=True)
    return result.stdout
