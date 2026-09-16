<div align="center">

<img src="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Crect x='13' y='5' width='38' height='54' rx='9' fill='%23b8ff45'/%3E%3Crect x='18' y='10' width='28' height='44' rx='5' fill='%23080b0a'/%3E%3Ccircle cx='32' cy='32' r='7' fill='none' stroke='%23b8ff45' stroke-width='3'/%3E%3Ccircle cx='32' cy='32' r='2' fill='%23b8ff45'/%3E%3C/svg%3E" width="90" alt="APK Analyzer Pro">

# APK Analyzer Pro

### Inspect Android APKs locally in your browser.

**Manifest · DEX · Permissions · Components · Technologies · Security · Files**

<br>

[![Live](https://img.shields.io/badge/live-APK%20Analyzer-b8ff45?style=flat-square\&labelColor=080b0a)](https://apk-analyzer.vercel.app/)
[![Source](https://img.shields.io/badge/source-GitHub-080b0a?style=flat-square)](https://github.com/iamlaxman/apk-analyzer)
[![Client Side](https://img.shields.io/badge/processing-100%25%20local-080b0a?style=flat-square)](https://github.com/iamlaxman/apk-analyzer)
[![Open Source](https://img.shields.io/badge/open-source-080b0a?style=flat-square)](https://github.com/iamlaxman/apk-analyzer)

</div>

---

## What it is

**APK Analyzer Pro** is a browser-based Android APK inspection tool.

Drop an APK into the analyzer and inspect its internal structure without sending the file to a server.

The application reads the APK directly in the browser and produces a structured report covering package information, manifest data, permissions, Android components, DEX statistics, detected technologies, native libraries, architectures, security findings, and the complete APK file tree.
The project is intentionally **local-first**:

```text
APK
 │
 ▼
Browser
 │
 ├── SHA-256
 ├── ZIP / APK structure
 ├── AndroidManifest.xml
 ├── DEX
 ├── Permissions
 ├── Components
 ├── Technologies
 ├── Native libraries
 ├── Signature information
 ├── Security checks
 └── File tree
        │
        ▼
   JSON report
```

No APK upload endpoint is required by the analyzer.

---

## Why

APK files contain considerably more information than the application icon and name shown to a normal Android user.

APK Analyzer makes that information easier to inspect.

Instead of immediately reaching for a large reverse-engineering toolchain, you can quickly answer questions such as:

```text
What package is this?

Which Android version does it target?

What permissions does it request?

Which activities, services, receivers and providers exist?

How many DEX files are included?

What native libraries are bundled?

Which ABIs are present?

What technologies can be identified?

Are there obvious security configuration issues?

What files are actually inside the APK?
```

---

## Features

### Local APK analysis

The analyzer accepts:

```text
.apk
.xapk
.apks
```

## The file is read using the browser's File API and processed in memory. The interface recommends APKs around **500 MB or smaller**, although there is no hard-coded maximum in the documentation.

### Package overview

The analyzer extracts package-level information from the decoded manifest and presents it as structured data.

The exported report includes the package object alongside the file hash and other analysis results.

---

### Android Manifest

`AndroidManifest.xml` is decoded and displayed as readable structured content.

The analyzer keeps both:

```text
Parsed manifest tree
        +
Readable manifest output
```

## and provides a copy action for the manifest view.

### Permissions

Requested Android permissions are extracted from the manifest and included in the analysis state and exported report.

The analyzer also surfaces security-related permission findings where applicable.

---

### Android components

The analysis keeps separate collections for:

```text
Activities
Services
Broadcast Receivers
Content Providers
```

These are included in the exported JSON report.

---

### DEX analysis

The analyzer detects:

```text
classes.dex
classes2.dex
classes3.dex
...
```

and parses each DEX file.

It calculates aggregate counts for:

* classes
* methods
* fields
* strings

The analyzer also extracts strings from DEX files for further inspection/detection.

The DEX interface presents individual DEX files with their size and statistics.

---

### Technology detection

The analyzer inspects the APK contents and attempts to identify technologies used by the application.

The detection stage runs after DEX parsing and native-library discovery.

Detected technologies are included in the JSON report as:

```json
{
  "name": "...",
  "kind": "..."
}
```

---

### Native libraries

Native `.so` files under:

```text
lib/
```

are collected automatically.

The analyzer also identifies ABI directories, allowing you to see architectures such as those represented by the APK's `lib/<architecture>/` paths.

---

### Signature inspection

The analyzer performs a signature-detection step as part of the analysis pipeline.

Signature information is included in the exported report.

---

### Security findings

After parsing the APK, the analyzer runs its security scan.

Findings are grouped by severity:

```text
Critical
High
Medium
Info
```

The interface displays severity counts and individual findings.

The scanner is intended to surface common security issues and configuration problems.

It is **not an antivirus and does not contain a malware signature database**.

---

## APK file explorer

The `Files` view presents the internal APK structure as an expandable tree.

```text
APK
├── AndroidManifest.xml
├── classes.dex
├── classes2.dex
├── res/
│   ├── drawable/
│   ├── layout/
│   └── values/
├── assets/
├── lib/
│   ├── arm64-v8a/
│   └── armeabi-v7a/
└── META-INF/
```

The actual tree is generated from the archive entries rather than being a hard-coded representation.

---

## File search

The file explorer includes:

* live search
* automatic expansion of matching folders
* expand all
* collapse all
* recursive folder counts
* file sizes
* extraction controls

Searching a filename automatically expands matching branches of the tree.

---

## File extraction

Individual files can be extracted directly from the APK.

Folders can also be packed back into ZIP archives while preserving their internal structure.

The analyzer can additionally package the complete APK contents into:

```text
<apk-name>-contents.zip
```

## All of this happens in the browser using JSZip.

## JSON reports

After analysis, the complete report can be exported as JSON.

The generated report contains:

```text
generatedAt
tool
file
package
signature
permissions
components
dex
technologies
nativeLibraries
architectures
sizeBreakdown
findings
entries
```

The file information includes:

```text
filename
size
SHA-256
```

and the file entries contain their names and sizes.

Example:

```json
{
  "generatedAt": "...",
  "tool": "APK Analyzer Pro",
  "file": {
    "name": "app.apk",
    "size": 50537472,
    "sha256": "..."
  },
  "package": {},
  "signature": {},
  "permissions": [],
  "components": {},
  "dex": {},
  "technologies": [],
  "nativeLibraries": [],
  "architectures": [],
  "sizeBreakdown": {},
  "findings": [],
  "entries": []
}
```

---

## Privacy

The analyzer is designed around a simple rule:

> **The APK stays in your browser.**

The application reads the selected file with the browser's File API, processes the archive in memory, and generates results locally.

The project documentation explicitly states that APKs do not leave the device during analysis.

There is no account requirement in the analyzer interface.

---

## What it does not do

APK Analyzer Pro is deliberately focused on inspection rather than full reverse engineering.

It does **not**:

* decompile APKs into Java source
* replace JADX
* replace APKTool
* perform dynamic instrumentation
* emulate the application
* execute the APK
* act as an antivirus
* guarantee that an APK is malware-free

For full source decompilation, the project's documentation points toward dedicated tools such as JADX or APKTool.

---

## Architecture

The analyzer is implemented as a static browser application.

```text
┌───────────────────────────────┐
│          Browser UI            │
│                               │
│  Upload / Drag & Drop          │
│          │                    │
│          ▼                    │
│      ArrayBuffer              │
│          │                    │
│     ┌────┴────┐               │
│     │  JSZip  │               │
│     └────┬────┘               │
│          │                    │
│   ┌──────┼──────────────┐     │
│   ▼      ▼              ▼     │
│Manifest DEX          Files     │
│   │      │              │     │
│   └──────┼──────────────┘     │
│          ▼                    │
│     Analysis State             │
│          │                    │
│   ┌──────┼──────────────┐     │
│   ▼      ▼      ▼       ▼     │
│Security Tech  Signature  Size │
│   │                           │
│   └──────────┬────────────────┘
│              ▼
│        Results / Export       │
└───────────────────────────────┘
```

The main analyzer performs its processing entirely inside the page.

---

## Analysis Pipeline

When an APK is selected, the application follows roughly this sequence:

```text
01  Read file
02  Compute SHA-256
03  Open ZIP archive
04  Enumerate files
05  Decode AndroidManifest.xml
06  Process manifest
07  Parse DEX files
08  Extract DEX strings
09  Detect technologies
10  Detect native libraries
11  Detect architectures
12  Build file tree
13  Detect signature information
14  Run security scan
15  Calculate size breakdown
16  Render results
```

This sequence corresponds to the actual `analyzeFile()` implementation.

---

## Interface

The analyzer uses a developer-oriented interface with:

* dark background
* lime-green accent
* monospace metadata
* compact information cards
* sidebar navigation
* responsive mobile drawer
* animated loading states
* searchable file tree
* severity indicators
* copy controls
* keyboard shortcuts

The primary visual accent is:

```text
#B8FF45
```

with a dark interface built around near-black green-tinted surfaces.

The homepage uses the same product identity and describes the tool as a browser-based Android APK inspection application focused on privacy and fast analysis.

---

## Keyboard Shortcuts

Inside the analyzer:

| Shortcut   | Action                      |
| ---------- | --------------------------- |
| `Ctrl + E` | Export JSON report          |
| `Cmd + E`  | Export JSON report on macOS |
| `Esc`      | Close drawer                |
| `/`        | Focus file search           |
| `1`        | Overview                    |
| `2`        | Manifest                    |
| `3`        | DEX                         |
| `4`        | Security                    |
| `5`        | Technologies                |
| `6`        | Files                       |

The numbered view switching and export shortcuts are implemented directly in the analyzer.

---

## Documentation

The repository includes a dedicated `documentation.html` covering:

* analyzer workflow
* manifest inspection
* DEX analysis
* permissions
* security findings
* technology detection
* file tree
* extraction
* JSON reports
* keyboard shortcuts
* FAQ
* troubleshooting

## The documentation also explains limitations such as the lack of Java source decompilation and the absence of malware-signature scanning.

## Pages

```text
index.html
    └── Product landing page

apk-analyzer.html
    └── Main analyzer

documentation.html
    └── Documentation and reference

privacy.html
    └── Privacy policy

contact.html
    └── Contact page
```

These are the current top-level pages in the repository.

---

## Project Structure

```text
apk-analyzer/
│
├── index.html
├── apk-analyzer.html
├── documentation.html
├── contact.html
├── privacy.html
│
└── README.md
```

The application currently keeps the main UI and analysis logic inside the HTML application rather than using a traditional frontend build system. The main analyzer file is approximately 2,700 lines of source on GitHub.

---

## Run Locally

Clone the repository:

```bash
git clone https://github.com/iamlaxman/apk-analyzer.git
cd apk-analyzer
```

Because the project is a static browser application, no package installation or build step is required for the basic interface.

You can serve it with Python:

```bash
python3 -m http.server 8080
```

Then open:

```text
http://localhost:8080
```

For the analyzer:

```text
http://localhost:8080/apk-analyzer.html
```

---

## Browser Support

The project documentation targets modern:

* Chrome
* Firefox
* Safari
* Edge
* Opera

on desktop and mobile. Internet Explorer is not supported.

---

## File Size

There is no explicit hard file-size limit in the application.

However, the documentation recommends APKs of approximately:

```text
500 MB or less
```

because larger files depend heavily on available device memory and CPU resources when processed inside the browser.

---

## Security Research

APK Analyzer Pro can be useful for quick application-security reconnaissance and triage.

It can help surface:

```text
Manifest configuration
Permissions
Components
DEX metadata
Native libraries
ABIs
Technologies
Signing information
Security findings
File structure
```

It should be treated as an **inspection and analysis aid**, not as a complete security assessment.

A clean report does not establish that an application is safe.

---

## Responsible Use

Only analyze APKs that you are authorized to inspect.

Do not upload or publicly share proprietary APKs through issue trackers, repositories, or other public services.

The project's own documentation specifically recommends not attaching proprietary APKs to public GitHub issues.

---

## Roadmap

Possible future work:

* [ ] More manifest security checks
* [ ] Expanded technology detection
* [ ] More DEX metrics
* [ ] Better signature parsing
* [ ] Additional APK format handling
* [ ] More detailed permission analysis
* [ ] Improved security finding explanations
* [ ] Larger-file performance improvements
* [ ] More export formats
* [ ] Automated regression tests
* [ ] More detailed file-level inspection

---

## License

Add the project's intended open-source license here if one is not already present in the repository.

---

## Author

**Laxman Poudel**

GitHub:
https://github.com/iamlaxman

Repository:
https://github.com/iamlaxman/apk-analyzer

---

<div align="center">

**APK Analyzer Pro**

`LOCAL FIRST / OPEN SOURCE`

Built for inspecting Android packages without sending them away.

</div>
