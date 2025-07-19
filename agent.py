# agent.py - Ethical IP Scanning Agent (Command-Line)

import nmap
import subprocess
import json
import time
import os
from bs4 import BeautifulSoup
import requests
from dotenv import load_dotenv # NEW: Import load_dotenv from python-dotenv

# Load environment variables from .env file
load_dotenv() # NEW: Call this function to load variables

# --- Configuration ---
# TOGETHER AI API Configuration
TOGETHER_API_URL = "https://api.together.ai/v1/chat/completions"
# Choose a model from Together AI. Examples:
# "meta-llama/Llama-3-8b-chat-hf"
# "mistralai/Mixtral-8x7B-Instruct-v0.1"
# "mistralai/Mistral-7B-Instruct-v0.2"
TOGETHER_MODEL = "meta-llama/Llama-3-8b-chat-hf" # Or your preferred Together AI model

# IMPORTANT: Get API key from environment variable (loaded from .env)
TOGETHER_API_KEY = os.getenv("TOGETHER_API_KEY") # CHANGED: Get from environment

# --- Helper Functions ---

def run_nmap_scan(target_ip, scan_type="-sV -O -p-"):
    """
    Executes an Nmap scan and returns the XML output.
    -sV: Service version detection
    -O: OS detection
    -p-: Scan all ports (1-65535)
    -oX -: Output in XML format to stdout
    """
    print(f"[*] Starting Nmap scan on {target_ip} with options: {scan_type}...")
    try:
        scan_options = scan_type.split()
        
        # IMPORTANT: Adding 'sudo' here for root privileges required by Nmap
        command = ["sudo", "nmap"] + scan_options + ["-oX", "-", target_ip]
        
        process = subprocess.run(command, capture_output=True, text=True, check=True)
        print("[+] Nmap scan completed.")
        return process.stdout
    except subprocess.CalledProcessError as e:
        print(f"[-] Nmap scan failed: {e}")
        print(f"    Stderr: {e.stderr}")
        return None
    except FileNotFoundError:
        print("[-] Nmap command not found. Please ensure Nmap is installed and in your PATH.")
        return None

def parse_nmap_xml(xml_output):
    """
    Parses Nmap XML output to extract relevant information.
    Returns a dictionary of host information.
    """
    if not xml_output:
        return {}

    # Use 'lxml-xml' for proper XML parsing to avoid warnings
    soup = BeautifulSoup(xml_output, 'lxml-xml')
    hosts_info = {}

    for host_tag in soup.find_all('host'):
        ip_address = host_tag.find('address', addrtype='ipv4')['addr'] if host_tag.find('address', addrtype='ipv4') else 'N/A'
        hostname = host_tag.find('hostname')['name'] if host_tag.find('hostname') else 'N/A'
        status = host_tag.find('status')['state'] if host_tag.find('status') else 'N/A'

        ports_info = []
        for port_tag in host_tag.find_all('port'):
            port_id = port_tag['portid']
            protocol = port_tag['protocol']
            state = port_tag.find('state')['state'] if port_tag.find('state') else 'N/A'
            service_name = port_tag.find('service')['name'] if port_tag.find('service') else 'N/A'
            service_product = port_tag.find('service')['product'] if port_tag.find('service') and 'product' in port_tag.find('service').attrs else 'N/A'
            service_version = port_tag.find('service')['version'] if port_tag.find('service') and 'version' in port_tag.find('service').attrs else 'N/A'

            ports_info.append({
                'port': port_id,
                'protocol': protocol,
                'state': state,
                'service': service_name,
                'product': service_product,
                'version': service_version
            })

        os_match = host_tag.find('osmatch')['name'] if host_tag.find('osmatch') else 'N/A'

        hosts_info[ip_address] = {
            'hostname': hostname,
            'status': status,
            'os_match': os_match,
            'ports': ports_info
        }
    return hosts_info

def query_together_ai(messages):
    """
    Sends a list of messages to the Together AI LLM and returns the response.
    """
    # Check if API key is set (now from environment)
    if not TOGETHER_API_KEY:
        print("[-] Error: TOGETHER_API_KEY is not set. Please ensure it's in your .env file.")
        return "Error: Together AI API key not configured."

    print(f"[*] Querying Together AI with {len(messages)} messages...")
    try:
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {TOGETHER_API_KEY}'
        }
        data = {
            "model": TOGETHER_MODEL,
            "messages": messages, # Together AI expects a list of messages
            "max_tokens": 1024, # Adjust as needed
            "temperature": 0.7, # Adjust creativity
            "top_p": 0.7,
            "top_k": 50,
            "repetition_penalty": 1 # Adjust to avoid repetition
        }
        response = requests.post(TOGETHER_API_URL, headers=headers, data=json.dumps(data))
        response.raise_for_status() # Raise an HTTPError for bad responses (4xx or 5xx)
        result = response.json()
        print("[+] Together AI response received.")
        
        # Extract the content from the response
        if result and result.get('choices') and result['choices'][0].get('message') and result['choices'][0]['message'].get('content'):
            return result['choices'][0]['message']['content'].strip()
        else:
            print(f"[-] Unexpected response structure from Together AI: {result}")
            return "Error: Unexpected response structure from Together AI."
            
    except requests.exceptions.ConnectionError:
        print(f"[-] Could not connect to Together AI. Check your internet connection or API URL.")
        return "Error: Could not connect to Together AI."
    except requests.exceptions.RequestException as e:
        print(f"[-] Error querying Together AI: {e}")
        return f"Error: {e}"

def generate_analysis_prompt_messages(scan_results):
    """
    Generates a list of messages for the LLM based on scan results,
    suitable for chat completion APIs like Together AI.
    """
    if not scan_results:
        return [{"role": "user", "content": "Nmap scan yielded no results. Please provide a summary of an empty scan."}]

    prompt_content = [
        "Analyze the following Nmap scan results. Focus on identifying potentially interesting open ports, services, and operating systems. Suggest next *legitimate* steps for further reconnaissance or vulnerability assessment, such as looking for public exploits for identified services, or performing more detailed scans on specific ports. Do not suggest any illegal or unethical actions like exploiting vulnerabilities without permission, or generating attack payloads."
    ]

    for ip, info in scan_results.items():
        prompt_content.append(f"\n--- Host: {ip} ---")
        prompt_content.append(f"  Hostname: {info['hostname']}")
        prompt_content.append(f"  Status: {info['status']}")
        prompt_content.append(f"  OS Match: {info['os_match']}")
        prompt_content.append("  Open Ports:")
        if info['ports']:
            for port in info['ports']:
                if port['state'] == 'open':
                    prompt_content.append(
                        f"    - Port: {port['port']}/{port['protocol']} | Service: {port['service']} "
                        f"| Product: {port['product']} | Version: {port['version']}"
                    )
        else:
            prompt_content.append("    No open ports found.")
        
    return [{"role": "user", "content": "\n".join(prompt_content)}]

def main():
    """
    Main function to orchestrate the scanning and analysis process.
    """
    target_ip = input("Enter the target IP address or range (e.g., 192.168.1.1 or 192.168.1.0/24): ")

    # Initialize chat history for the session
    chat_history = []

    # Step 1: Run Initial Nmap Scan
    nmap_xml_output = run_nmap_scan(target_ip)

    if nmap_xml_output:
        # Step 2: Parse Nmap XML Output
        parsed_results = parse_nmap_xml(nmap_xml_output)
        print("\n--- Parsed Nmap Results ---")
        print(json.dumps(parsed_results, indent=2))

        if parsed_results:
            # Step 3: Generate Analysis Prompt for LLM (as messages)
            llm_prompt_messages = generate_analysis_prompt_messages(parsed_results)
            chat_history.extend(llm_prompt_messages) # Add user's initial prompt to history

            # Step 4: Query Together AI for Analysis
            ollama_analysis = query_together_ai(chat_history)
            print("\n--- AI Analysis and Suggestions (from Together AI) ---")
            print(ollama_analysis)
            chat_history.append({"role": "assistant", "content": ollama_analysis}) # Add AI's response to history

            # --- Interactive Follow-up Scans (CLI) ---
            print("\n--- Follow-up Scan Interface ---")
            while True:
                follow_up_command_str = input(
                    "Enter a specific Nmap command (e.g., '-p 3306 --script mysql-info') "
                    "for the target, or type 'quit' to exit: "
                )
                if follow_up_command_str.lower() == 'quit':
                    break
                if not follow_up_command_str.strip():
                    print("No command entered. Please try again or type 'quit'.")
                    continue

                # Execute the follow-up Nmap command
                print(f"\n[*] Running follow-up Nmap scan with options: {follow_up_command_str}...")
                
                follow_up_xml_output = run_nmap_scan(target_ip, scan_type=follow_up_command_str)

                if follow_up_xml_output:
                    follow_up_parsed_results = parse_nmap_xml(follow_up_xml_output)
                    print("\n--- Follow-up Scan Parsed Results ---")
                    print(json.dumps(follow_up_parsed_results, indent=2))

                    # OPTIONAL: Feed these follow-up results back to LLM for new analysis
                    # Generate a new prompt including the latest scan results and previous history
                    follow_up_llm_prompt_content = f"Given our previous conversation and the new scan results for {target_ip}:\n{json.dumps(follow_up_parsed_results, indent=2)}\n\nPlease provide further analysis and suggestions based on this new information."
                    chat_history.append({"role": "user", "content": follow_up_llm_prompt_content})
                    
                    follow_up_llm_analysis = query_together_ai(chat_history) # Pass updated history
                    print("\n--- AI Analysis of Follow-up Scan (from Together AI) ---")
                    print(follow_up_llm_analysis)
                    chat_history.append({"role": "assistant", "content": follow_up_llm_analysis}) # Add AI's response to history

                else:
                    print("[-] Follow-up Nmap scan failed.")

        else:
            print("\nNo hosts found or no open ports in the Nmap scan results to analyze.")
    else:
        print("\nFailed to get Nmap scan output. Exiting.")

if __name__ == "__main__":
    main()
