# GitHook Pre-Push Virus Scanner

## Project Title and Description
The **GitHook Pre-Push Virus Scanner** is a security automation tool designed to improve repository safety by scanning files for viruses or malware **before they are pushed** to a remote Git repository.  

This project acts as an **information retrieval and analysis tool** that integrates with Git’s pre-push hook system. It scans staged files using a virus scanning API, generates a report summarizing scan results, and blocks infected files from being pushed.  

This ensures that teams and individual developers maintain clean, secure repositories and prevent malware from spreading through shared version control systems.

---

## Team Member Names and Roles
**Group Members:**  
- **Jeremiah Carr** — *Project Manager*  
- **Andrew Smith** — *Project Organizer*  
- **Tsion Kebede** — *Project Implementer*  
- **Lina Romero-Fabian** — *Project Designer*  

---

## Domain Focus and Problem Statement
**Domain Focus:** Information Retrieval and Analysis Tool  

**Problem Statement:**  
Every day, thousands of files are pushed to online repositories by developers across the world. Some of these files may unknowingly contain malware or other harmful code. This poses a significant security risk to organizations, open-source communities, and individuals alike.

Our project addresses this issue by developing a **Git-integrated virus scanner** that automatically checks all files staged for commit before a push occurs. If a file is found to be unsafe, the push is blocked, and a clear report is provided to the user.

**Who this helps:**  
- Software developers  
- Companies managing internal repositories  
- Open-source maintainers  
- Anyone who contributes to shared Git repositories  

**Why it matters:**  
This tool promotes safe collaboration, reduces the risk of introducing malware, and encourages secure coding practices within development environments.

---

## Installation and Setup Instructions

### Prerequisites
- **Python 3.10 or higher**  
- **Git** installed and configured  
- A **Virus Scanning API key** (Virus Total)  
- Internet access for API-based scanning  

### Setup Steps

1. **Clone the Repository**
   ```bash
   git clone https://github.com/your-org/GitHook-VirusScanner.git
   cd GitHook-VirusScanner

2. Install Requried Dependencies
pip install -r requirements.txt

3. Create Configuration File
{
  "api_key": "your_api_key_here",
  "base_url": "https://api.virusscanner.com/v3/files",
  "timeout_s": 30,
  "scan_timeout_s": 120,
  "poll_interval_s": 2
}

4. Install Pre-Push Hook
python -c "import function_library as fl; fl.install_pre_push_hook('.')"

5. Test 