# Usage Examples and Tutorials

This document provides **hands-on examples** and **tutorials** for using the functions from `function_library.py`.  
It demonstrates how to set up, test, and run the Git pre-push virus scanner in real-world workflows.

---

## Overview

The pre-push scanner automatically checks all staged files in your Git repository for potential malware using the VirusTotal API **before you push** your code.  

By integrating with Git hooks, it helps prevent infected or unsafe files from being uploaded to shared repositories.

---

## Prerequisites

Before running these examples, ensure that:
- Python ≥ 3.9 is installed.  
- `requests` library is installed:
  ```bash
  pip install requests
