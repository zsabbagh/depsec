import subprocess, datetime, os, json, lizard
from pathlib import Path
from loguru import logger
# This file includes the running of other programmes or modules

def get_files(dir: str, includes: list = None, excludes: list = None) -> list:
    """
    Get all files in a directory, optionally filtered by includes and excludes.
    """
    pass

def run_lizard(dir: str | Path, includes: list = None, excludes: list = None) -> dict:
    """
    Runs Lizard on the codebase provided.
    """
    return {}

def run_bandit(dir: str | Path, output: str | Path = None) -> None:
    """
    Run Bandit on the codebase.
    """
    # Run Bandit
    dir = Path(dir).absolute()
    output = Path(output).absolute() if output else Path('/tmp')
    dt = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
    fn = output / f'bandit-{dt}.json'
    if not dir.exists():
        logger.error(f"Directory '{dir}' does not exist!")
        return None
    logger.info("Running Bandit...")
    data = None
    try:
        subprocess.run(["bandit", "-r", str(dir), '-f', 'json', '-o', str(fn)])
        with open(fn, 'r') as f:
            data = json.load(f)
            return data
    except Exception as e:
        logger.error(f"Bandit found issues in the codebase: {e}")
        return None
