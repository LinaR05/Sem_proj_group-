# GitHook Pre-Push Virus Scanner

## Project Overview and Domain Problem

### Domain: Information Retrieval and Analysis Tool

The **GitHook Pre-Push Virus Scanner** is an **information retrieval and analysis tool** that automatically scans files for viruses and malware before they are pushed to remote Git repositories.

### Problem Statement
Every day, thousands of files are pushed to shared repositories by developers worldwide. Some of these files may unknowingly contain malware or harmful code, posing significant security risks to organizations, open-source communities, and individual developers.

Our scanner addresses this critical problem by:
- **Retrieving** file data from staged Git commits
- **Analyzing** files using the VirusTotal API (70+ antivirus engines)
- **Reporting** scan results with detailed detection information
- **Blocking** infected files from being pushed to repositories

This tool acts as an automated security gatekeeper, ensuring only clean, safe files enter shared codebases.

### Why This Matters
- **Prevents malware spread** through version control systems
- **Protects teams** from accidentally introducing security vulnerabilities
- **Promotes secure coding practices** in development workflows
- **Maintains repository integrity** across collaborative projects

---

## Team Members and Contributions

**Group Members:**
- **Jeremiah Carr** — *Project Manager*
  - Coordinated project timeline and milestones
  - Organized team meetings and communication
  - Managed task distribution and deadlines

- **Andrew Smith** — *Project Organizer*
  - Structured project architecture and workflow
  - Coordinated integration between components
  - Organized documentation and deliverables

- **Tsion Kebede** — *Project Implementer*
  - Implemented core scanning functionality
  - Developed API integration with VirusTotal
  - Built file analysis and detection logic

- **Lina Romero-Fabian** — *Project Designer*
  - Designed OOP architecture and class hierarchies
  - Created design patterns implementation
  - Developed data persistence features

---

## Setup and Installation Instructions

### Prerequisites
Before you begin, ensure you have:
- **Python 3.9 or higher** installed
- **Git** installed and configured
- A **VirusTotal API key** (free at [virustotal.com](https://www.virustotal.com/))
- **Internet connection** for API access

### Step-by-Step Installation

#### 1. Clone the Repository
```bash
git clone https://github.com/LinaR05/GitHook-VirusScanner.git
cd GitHook-VirusScanner
```


#### 2. Install Required Dependencies
```bash
pip install requests
```

*That's it! The scanner only requires the `requests` library.*

#### 3. Get Your VirusTotal API Key
1. Visit [https://www.virustotal.com/](https://www.virustotal.com/)
2. Sign up for a free account
3. Go to your profile and copy your API key
4. Keep this key secure - you'll need it in the next step

#### 4. Create Configuration File
Create a file named `virus_scan_config.json` in the repository root with your API key:
```json
{
  "api_key": "YOUR_VIRUSTOTAL_API_KEY_HERE",
  "base_url": "https://www.virustotal.com/api/v3",
  "timeout_s": 120,
  "scan_timeout_s": 300,
  "poll_interval_s": 5
}
```

**IMPORTANT SECURITY STEP:**
```bash
# Add config file to .gitignore to protect your API key
echo "virus_scan_config.json" >> .gitignore
```

#### 5. Verify Installation
```bash
# Run the scanner (should show "No staged files to scan")
python run.py
```

If you see the virus scanner banner, you're ready to go! 🎉

---

## Basic Usage Guide with Examples

### Example 1: Scanning Clean Files

**Step 1:** Create and stage a clean file
```bash
# Create a simple Python file
echo "print('Hello, World!')" > hello.py

# Stage it for scanning
git add hello.py
```

**Step 2:** Run the scanner
```bash
python run.py
```

**Expected Output:**
```
Virus Scanner 

[scanner] Starting scan...

[scanner] ⟳ Uploading new file to VirusTotal: hello.py
[scanner] ⟳ File uploaded successfully. Analysis ID: abc123...
[scanner] ✓ Analysis complete: 0/70 detected malicious

Scan Report:
- hello.py: CLEAN (status=completed, detections=0)

[scanner] Scan history saved to scan_history.jsonl
[scanner] All files clean. OK to push.

==================================================
Recent Scan History (last 5 scans)
==================================================
1. [2025-12-09T20:15:30.123456]
   Files: 1 | Status: ALLOWED

==================================================

Exit code: 0
```

---

### Example 2: Testing with EICAR (Safe Malware Test)

The **EICAR test file** is a harmless text string that all antivirus programs detect as "malware" by international agreement. It's perfect for testing without using real malware.

**Step 1:** Create the EICAR test file
```bash
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > eicar_test.txt
```

**Step 2:** Stage and scan
```bash
git add eicar_test.txt
python run.py
```

**Expected Output:**
```
Virus Scanner

[scanner] Starting scan...

[scanner] ✓ File already in VirusTotal database: eicar_test.txt
[scanner] ✓ Analysis complete: 63/70 detected malicious

Scan Report:
- eicar_test.txt: INFECTED (status=completed, detections=63)

[scanner] Scan history saved to scan_history.jsonl
[scanner] Push blocked by ScanSession evaluation.
[scanner] Infection detected! Push blocked.

==================================================
Recent Scan History (last 5 scans)
==================================================
1. [2025-12-09T20:16:45.789012]
   Files: 1 | Status: BLOCKED

==================================================

Exit code: 1
```

**Result:** Push is blocked!

---

### Example 3: Scanning Multiple Files

**Step 1:** Stage multiple files
```bash
git add src/utils.py src/main.py docs/README.md
```

**Step 2:** Run the scanner
```bash
python run.py
```

**Output shows all files scanned:**
```
Scan Report:
- src/utils.py: CLEAN (status=completed, detections=0)
- src/main.py: CLEAN (status=completed, detections=0)
- docs/README.md: CLEAN (status=completed, detections=0)

[scanner] All files clean. OK to push.
```

---

### Example 4: Viewing Scan History

Your scan history is automatically saved to `scan_history.jsonl`. View it:
```bash
# View raw history (JSONL format)
cat scan_history.jsonl

# Or just run the scanner - it shows last 5 scans
python run.py
```

**History shows:**
- When each scan occurred (timestamp)
- How many files were scanned
- Whether the push was allowed or blocked

---

### Example 5: Understanding File Types

The scanner automatically detects file types and uses appropriate strategies:
```bash
# Source code files (.py, .js, .java)
git add main.py
python run.py
# Uses: Hash Lookup Strategy (fast)

# Binary files (.exe, .zip, .bin)
git add app.exe
python run.py
# Uses: Chunked Upload Strategy (for large files)

# Manifest files (requirements.txt, package.json)
git add requirements.txt
python run.py
# Uses: Manifest Insight Strategy (analyzes dependencies)
```

---

## How to Run Tests

We have a comprehensive test suite with **19 tests** covering unit, integration, and system testing.

### Run All Tests
```bash
# Discover and run all tests with verbose output
python -m unittest discover tests -v
```

### Expected Output
```
test_compute_file_sha256 (tests.test_project_4.TestUnitPrimitives) ... ok
test_is_binary_file_detects_binary (tests.test_project_4.TestUnitPrimitives) ... ok
test_is_binary_file_detects_text (tests.test_project_4.TestUnitPrimitives) ... ok
...
test_end_to_end_clean_file_allowed (tests.test_project_4.TestSystemCompleteCleanScan) ... ok
test_end_to_end_infected_file_blocked (tests.test_project_4.TestSystemCompleteInfectedScan) ... ok
...

----------------------------------------------------------------------
Ran 19 tests in 2.345s

OK
```

### Run Specific Test Categories

**Unit Tests Only:**
```bash
python -m unittest tests.test_project_4.TestUnitPrimitives -v
python -m unittest tests.test_project_4.TestUnitArtifacts -v
```

**Integration Tests Only:**
```bash
python -m unittest tests.test_project_4.TestIntegrationArtifactFactory -v
python -m unittest tests.test_project_4.TestIntegrationDataPersistence -v
```

**System Tests Only:**
```bash
python -m unittest tests.test_project_4.TestSystemCompleteCleanScan -v
python -m unittest tests.test_project_4.TestSystemCompleteInfectedScan -v
```

### Test Coverage Summary

Our test suite includes:

**8 Unit Tests:**
- SHA-256 hash computation
- Binary vs text file detection
- Scan result interpretation
- Push blocking logic
- Artifact metadata generation

**6 Integration Tests:**
- Factory pattern creating correct artifact types
- Strategy registry assigning appropriate strategies
- Data persistence (save and load)
- ScanSession orchestrating all components
- Hook polymorphism (PrePushHook vs ManualScanHook)

**5 System Tests:**
- Complete clean file scan workflow
- Complete infected file scan and blocking
- Multi-file scanning with mixed results
- Persistence across multiple scan sessions
- JSON config import and JSONL history export

### Troubleshooting Tests

**If tests fail:**
```bash
# 1. Check Python version (must be 3.9+)
python --version

# 2. Ensure requests library is installed
pip install requests

# 3. Make sure you're in the project root directory
cd /path/to/GitHook-VirusScanner

# 4. Try running tests again
python -m unittest discover tests -v
```

---

## Project Architecture

### File Structure
```
GitHook-VirusScanner/
├── src/
│   ├── virus_scanner_core.py    # Core utilities & API integration
│   └── scanner_models.py         # OOP classes & design patterns
├── tests/
│   └── test_project_4.py         # Comprehensive test suite (19 tests)
├── run.py                        # Main entry point
├── virus_scan_config.json        # API configuration (DON'T COMMIT)
├── scan_history.jsonl            # Persistent scan history
├── .gitignore                    # Protects sensitive files
└── README.md                     # This file
```

### Key Components

#### **virus_scanner_core.py** - Core Utilities
Low-level functions for:
- VirusTotal API communication (submit_scan, poll_scan_completion)
- File operations (compute_file_sha256, is_binary_file)
- Git integration (get_staged_file_paths, detect_git_repository_root)
- Result interpretation (interpret_scan_result, should_block_push)

#### **scanner_models.py** - OOP Design
Object-oriented classes implementing:

**1. Artifact Hierarchy (Polymorphism):**
```
ScanArtifact (Abstract Base Class)
├── SourceCodeArtifact    # Python, JavaScript, Java files
├── BinaryArtifact        # Executables, archives, binaries
└── ManifestArtifact      # requirements.txt, package.json
```

**2. Strategy Pattern:**
```
AbstractScanStrategy (Abstract Base Class)
├── HashLookupStrategy       # Fast hash-based scanning
├── ChunkedUploadStrategy    # For large binary files
└── ManifestInsightStrategy  # Analyzes dependencies
```

**3. Hook Pattern:**
```
HookBase (Abstract Base Class)
├── PrePushHook      # Git pre-push integration
└── ManualScanHook   # On-demand file scanning
```

**4. Composition:**
- `ScanSession` - Orchestrates entire scan workflow
- `ArtifactFactory` - Creates appropriate artifact types
- `ScanStrategyRegistry` - Assigns optimal scanning strategy

---

## Data Persistence Features

### Scan History Storage
Every scan is automatically saved to `scan_history.jsonl` with:
- **Timestamp:** Unix timestamp and ISO format datetime
- **Files Scanned:** Count and list of all files
- **Results:** Individual scan results per file
- **Verdict:** Clean/infected status for each file
- **Block Status:** Whether push was allowed or blocked

**Example History Entry:**
```json
{
  "timestamp": 1702156530.123,
  "datetime": "2025-12-09T20:15:30.123456",
  "repo_root": "/Users/you/projects/your-repo",
  "file_count": 2,
  "results": {
    "clean.py": {
      "status": "completed",
      "clean": true,
      "detections": 0,
      "total": 70
    },
    "virus.exe": {
      "status": "completed",
      "clean": false,
      "detections": 47,
      "total": 70
    }
  },
  "verdict": {
    "clean.py": true,
    "virus.exe": false
  },
  "blocked": true
}
```

### Loading History
The scanner automatically displays your last 5 scans when you run it. You can also access the full history programmatically:
```python
from src.scanner_models import ScanSession

session = ScanSession()
history = session.load_scan_history(limit=10)  # Get last 10 scans
```

---

## Design Patterns Implemented

Our project demonstrates professional software design patterns:

1. **Abstract Base Classes** - Enforces interface contracts
2. **Factory Pattern** - ArtifactFactory creates appropriate types
3. **Strategy Pattern** - Different strategies for different file types
4. **Polymorphism** - Single interface works with multiple implementations
5. **Composition** - ScanSession composes multiple components
6. **Dependency Injection** - API client injected into session

---

## Security Considerations

### API Key Protection
**CRITICAL:** Never commit your API key to version control!
```bash
# Always add to .gitignore
echo "virus_scan_config.json" >> .gitignore

# Verify it's ignored
git status
```

### EICAR Test File Safety
The EICAR test file is **completely safe** - it's just a text string:
```
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
```

It's recognized as "malware" by international agreement for testing purposes. You can safely create, scan, and delete it.

### Rate Limits
VirusTotal free tier limits:
- **4 requests per minute**
- **500 requests per day**

Plan your testing accordingly or consider a premium API key for production use.

---

## Troubleshooting

### "401 Unauthorized" Error
**Problem:** API key is invalid or missing

**Solution:**
1. Check `virus_scan_config.json` exists in repo root
2. Verify your API key is correct (64 characters)
3. Test your key at [virustotal.com](https://www.virustotal.com/)

### "No staged files to scan"
**Problem:** No files are staged in Git

**Solution:**
```bash
# Check what's staged
git status

# Stage files
git add your_file.py

# Run scanner again
python run.py
```

### "File not in VirusTotal database"
**Problem:** New file hasn't been scanned yet

**Solution:**
- First scan of new files takes 1-5 minutes
- The scanner uploads the file automatically
- Run the scan again after a few minutes to get results

### Tests Failing
**Problem:** Dependencies or environment issues

**Solution:**
```bash
# 1. Check Python version (3.9+ required)
python --version

# 2. Install dependencies
pip install requests

# 3. Run tests from project root
cd /path/to/GitHook-VirusScanner
python -m unittest discover tests -v
```

---

## Known Limitations

1. **First scan delay:** New files require 1-5 minutes for VirusTotal analysis
2. **API rate limits:** Free tier limited to 4 requests/minute
3. **Internet required:** Scanner needs active internet connection
4. **File size limit:** VirusTotal has 650MB limit per file
5. **False negatives possible:** Depends on VirusTotal's detection database

---

## Future Enhancements

Potential improvements for future versions:
- [ ] Automatic git hook installation script
- [ ] Local caching to reduce API calls
- [ ] Support for multiple scanning APIs
- [ ] Web dashboard for scan history visualization
- [ ] Email notifications for blocked pushes
- [ ] CI/CD pipeline integration
- [ ] Whitelist/blacklist file support

---

## Frequently Asked Questions

**Q: Do I need to pay for VirusTotal?**  
A: No! The free tier is sufficient for this project.

**Q: Will this slow down my git workflow?**  
A: Files already in VirusTotal's database get instant results. New files take 1-5 minutes on first scan.

**Q: Can I use this in production?**  
A: Yes, but consider getting a premium VirusTotal API key for higher rate limits.

**Q: What if I don't have internet?**  
A: The scanner requires internet to access the VirusTotal API. It won't work offline.

**Q: Is the EICAR file dangerous?**  
A: No! It's a harmless test file specifically designed for testing antivirus software.

---

## Contributing

This project is part of an academic course, but contributions are welcome for educational purposes:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Add tests for new features
4. Submit a pull request

---

## License

This project is developed for educational purposes as part of a semester-long Object-Oriented Programming course.

---

## Acknowledgments

- **VirusTotal** for providing the comprehensive malware scanning API
- **Python requests library** for simplified HTTP communication
- Course instructors for guidance on OOP design patterns
- Team members for collaborative development and testing

---

## Support and Contact

For questions, issues, or contributions:
- **Create an issue** on GitHub
- **Contact team members** listed above
- **Check VirusTotal documentation** at [docs.virustotal.com](https://docs.virustotal.com/)

---

**Project Version:** 4.0 (Final Submission)  
**Last Updated:** December 2025  
**Course:** Object-Oriented Programming  
**Domain:** Information Retrieval and Analysis Tool