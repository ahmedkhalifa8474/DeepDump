import os
import json
import csv
import logging
import requests
from volatility.plugins import pslist, dlllist, cmdscan, netscan, malfind, strings # type: ignore
from volatility import framework # type: ignore
from volatility.framework import interfaces # type: ignore
from datetime import datetime

# ASCII Banner
BANNER = """
  DDDD  EEEEE  EEEEE  PPPP   DDDD  U   U  M   M  PPPP
  D   D E      E     P   P  D   D U   U  MM MM  P   P
  D   D EEEE   EEEE  PPPP   D   D U   U  M M M  PPPP
  D   D E      E     P      D   D U   U  M   M  P
  DDDD  EEEEE  EEEEE P      DDDD   UUU   M   M  P
"""

print(BANNER)

# Configurable parameters (can be changed in config.json)
CONFIG_FILE = "config.json"

# API Keys and URLs
VIRUSTOTAL_API_KEY = "e20703e48bc155a08acd59b0aba44f66446d88c6fdadb6f690c0bf819d556e0c"
ABUSEIPDB_API_KEY = "a2b2f394cf6fa3171be74816f09246b400dde22a8e81f0a15ffd8ab7bf99033be57f7de71e3297df"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/files/"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

# Set up logging
logging.basicConfig(filename='memory_analysis.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load configuration
def load_config():
    try:
        with open(CONFIG_FILE, 'r') as config_file:
            return json.load(config_file)
    except Exception as e:
        logging.error(f"Error loading config file: {e}")
        return {}

# Collect memory dump (simulated, should use WinPMEM or another tool)
def collect_memory_dump(output_path):
    # Simulate memory dump collection
    try:
        logging.info(f"Collecting memory dump to {output_path}")
        # Replace this with actual memory collection logic using tools like WinPMEM
        os.system(f"dd if=/dev/mem of={output_path} bs=1M")
    except Exception as e:
        logging.error(f"Error collecting memory dump: {e}")

# Analyze memory dump using Volatility 2
def analyze_memory_dump(dump_file):
    try:
        logging.info(f"Analyzing memory dump: {dump_file}")
        
        # Example of loading plugins
        context = framework.context.Context()
        framework.set_context(context)

        pslist_results = pslist.PSList()
        dlllist_results = dlllist.DLLList()
        cmdscan_results = cmdscan.CmdScan()
        netscan_results = netscan.NetScan()
        strings_results = strings.Strings()
        malfind_results = malfind.Malfind()

        # Run the analysis
        pslist_results.calculate(dump_file)
        dlllist_results.calculate(dump_file)
        cmdscan_results.calculate(dump_file)
        netscan_results.calculate(dump_file)
        strings_results.calculate(dump_file)
        malfind_results.calculate(dump_file)

        return {
            "pslist": pslist_results.get_results(),
            "dlllist": dlllist_results.get_results(),
            "cmdscan": cmdscan_results.get_results(),
            "netscan": netscan_results.get_results(),
            "strings": strings_results.get_results(),
            "malfind": malfind_results.get_results()
        }
    except Exception as e:
        logging.error(f"Error analyzing memory dump: {e}")
        return {}

# Compare with baseline (from a previous analysis)
def compare_baseline(current_data, baseline_file="baseline.json"):
    try:
        if not os.path.exists(baseline_file):
            logging.info("No baseline file found. Creating new baseline.")
            with open(baseline_file, 'w') as file:
                json.dump(current_data, file)
            return {}
        
        with open(baseline_file, 'r') as file:
            baseline_data = json.load(file)
        
        # Compare current_data to baseline_data (you can compare specific fields)
        anomalies = {}
        for key, value in current_data.items():
            if key in baseline_data:
                baseline_value = baseline_data[key]
                anomalies[key] = [val for val in value if val not in baseline_value]
            else:
                anomalies[key] = value
        
        # Update the baseline file with the new data
        with open(baseline_file, 'w') as file:
            json.dump(current_data, file)

        return anomalies
    except Exception as e:
        logging.error(f"Error comparing with baseline: {e}")
        return {}

# Query IoC feeds (VirusTotal and AbuseIPDB)
def query_virustotal(file_hash):
    try:
        headers = {
            "x-apikey": VIRUSTOTAL_API_KEY
        }
        response = requests.get(f"{VIRUSTOTAL_URL}{file_hash}", headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            logging.warning(f"Error querying VirusTotal: {response.status_code}")
            return None
    except Exception as e:
        logging.error(f"Error querying VirusTotal: {e}")
        return None

def query_abuseipdb(ip):
    try:
        headers = {
            "Key": ABUSEIPDB_API_KEY
        }
        response = requests.get(f"{ABUSEIPDB_URL}?ipAddress={ip}", headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            logging.warning(f"Error querying AbuseIPDB: {response.status_code}")
            return None
    except Exception as e:
        logging.error(f"Error querying AbuseIPDB: {e}")
        return None

# Generate CSV report
def generate_csv_report(analysis_data, anomalies, output_path="report.csv"):
    try:
        with open(output_path, 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["Plugin", "Result"])
            for plugin, results in analysis_data.items():
                writer.writerow([plugin, results])
            writer.writerow([])
            writer.writerow(["Anomalies", "Details"])
            for anomaly, details in anomalies.items():
                writer.writerow([anomaly, details])
        logging.info(f"CSV report generated at {output_path}")
    except Exception as e:
        logging.error(f"Error generating CSV report: {e}")

# Main script execution
def main():
    try:
        # Load configuration
        config = load_config()
        memory_dump_path = config.get("memory_dump_path", "/tmp/memory_dump.raw")

        # Collect memory dump (if needed)
        collect_memory_dump(memory_dump_path)

        # Analyze the memory dump
        analysis_data = analyze_memory_dump(memory_dump_path)

        # Compare with baseline
        anomalies = compare_baseline(analysis_data)

        # Query IoC feeds (example: query file hash and IP)
        for plugin, data in analysis_data.items():
            if plugin == "pslist":
                for process in data:
                    if "ip" in process:
                        query_abuseipdb(process["ip"])

        # Generate CSV report
        generate_csv_report(analysis_data, anomalies)

    except Exception as e:
        logging.error(f"Error during main execution: {e}")

if __name__ == "__main__":
    main()
