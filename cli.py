import argparse
import asyncio
import logging
import os
import sys
from dotenv import load_dotenv

# Ensure src/ is on sys.path for local runs
repo_root = os.path.dirname(os.path.abspath(__file__))
src_path = os.path.join(repo_root, "src")
if os.path.isdir(src_path) and src_path not in sys.path:
    sys.path.insert(0, src_path)

from services.main_orchestrator import process_scan


def configure_logging() -> None:
    log_level = os.getenv("LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=getattr(logging, log_level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run vulnerability processing on an Nmap XML file"
    )
    parser.add_argument(
        "--xml", required=True, help="Path to Nmap XML file to process"
    )
    args = parser.parse_args()

    load_dotenv()
    configure_logging()

    with open(args.xml, "r", encoding="utf-8") as f:
        xml_content = f.read()

    result = asyncio.run(process_scan(xml_content))
    # Print a concise summary
    prioritized_services = result.get("summary", {}).get("prioritized_services")
    total_hosts = result.get("summary", {}).get("total_hosts")
    print({"total_hosts": total_hosts, "prioritized_services": prioritized_services})


if __name__ == "__main__":
    main()


