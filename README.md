

# 🛡️ Ethical IP Scanning Agent (Command-Line)

A command-line tool for **ethical network reconnaissance** using **Nmap** and **Large Language Models** (via Together AI). Designed for responsible cybersecurity auditing, this agent provides intelligent interpretation of scan results and offers suggestions for **legitimate next steps**.

---

## ⚠️ Disclaimer

> **This tool is for educational and ethical purposes only.**

* **You must have explicit, written permission** before scanning any network or system you do not own or manage.
* Unauthorized scanning is **illegal and unethical**.
* This tool uses `sudo` to run certain Nmap scans, which require **elevated privileges**—**use responsibly and only in authorized environments**.

---

##  Features

* 🔍 **Nmap Integration**
  Perform advanced scans including:

  * Service version detection
  * OS fingerprinting
  * Full port sweeps

*  **LLM-Powered Analysis**

  * Uses the **Together AI API** to:

    * Interpret Nmap XML output
    * Summarize network insights
    * Suggest **ethical** follow-up actions

*  **Interactive CLI Workflow**

  * Iterative scanning and analysis
  * Input custom Nmap commands based on LLM insights or manual expertise

*  **Contextual AI Responses**

  * Maintains basic chat memory for relevant, session-aware responses

* 📂 **Structured Output**

  * Converts raw Nmap XML to **human-readable JSON**

---

## ⚙️ Prerequisites

Make sure your **macOS (Apple M2)** device has the following:

*  Python 3.x (usually pre-installed)
*  Homebrew (macOS package manager)
*  Nmap (`brew install nmap`)
*  Together AI API key from [together.ai](https://together.ai/)

---

## 🚀 Setup & Usage

Detailed installation and usage instructions can be found in:

setup_run.pdf

Includes:

* Installation steps
* API configuration
* Running your first scan
* Viewing and interpreting results

---

## ✅ Ethical Guidelines

* The LLM is **explicitly prompted** to **avoid illegal, intrusive, or unethical behavior**.
* Final responsibility lies with **you**, the user, to ensure:

  * All scans are **authorized**
  * All actions comply with **cybersecurity laws** and **ethical norms**


---

>  Built with ethical hacking principles.
>  Use responsibly. Think before you scan.
