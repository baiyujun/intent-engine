import subprocess, sys, pathlib

def test_run_pipeline_help():
    r = subprocess.run([sys.executable, "scripts/run_pipeline.py", "--help"], capture_output=True, text=True)
    assert r.returncode == 0
    assert "--sources" in r.stdout and "--all" in r.stdout
