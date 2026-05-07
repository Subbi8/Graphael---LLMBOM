# Gauntlet-sbom-universal-generator
SBOM generator for unstructured projects

- **SBOM Output Excel Sheet**: [view combined_sbom](https://docs.google.com/spreadsheets/d/1ODvRoeWzqV4ZL4L1XW16eAY8PlFr_sXdSSS_EIIqMxM/edit?usp=sharing)
  _This Excel sheet contains the consolidated SBOM results generated from multiple tested repositories._

- **Tested GitHub Repositories**: [View repository_list](https://docs.google.com/spreadsheets/d/1-4g7qFLjJtZuPGpQTHFjt49TSA0jHn27H8jawD73Zpk/edit?usp=sharing)
  _This link includes the list of GitHub repositories on which the SBOM analysis was performed._

## Supported Languages

- **C/C++**: Analyzes include statements and library dependencies
- **.NET**: Supports C#, F#, and .NET projects
- **PHP**: Extracts PHP package dependencies

## Features

- **Multi-format Output**: Generates both JSON and CSV SBOM reports
- **Duplicate Removal**: Automatically removes duplicate packages
- **Standard Library Filtering**: Excludes built-in/standard libraries from results
- **Flexible Language Support**: Easily extensible for additional languages
- **AI-Powered Vendor Detection**: Uses local LLMs (like Qwen:14B via Ollama) with web context to determine the most likely vendor of each package.

## Project Structure

```
sbom-generator/
├── main.py                 # Entry point and CLI interface
├── extractor.py           # Main extractor class and SBOM
├── c_cpp.py              # C/C++ specific package extraction
├── dotnet.py             # .NET (C#, F#) package extraction
├── php.py                # PHP package extraction
├── standard_lib.py       # Standard library definitions
└── result/               # Generated SBOM output directory
    └── [project_name]/
        ├── [category]_sbom.json
        └── [category]_sbom.csv
```

## Usage

### Command Line Interface

```bash
python main.py <project_path> <language>
```

### Parameters

- `project_path`: Path to the project directory to analyze
- `language`: Programming language of the project

### Supported Language Values

- **C/C++**: `c`, `c++`, `cpp`
- **.NET**: `csharp`, `c#`, `cs`, `f#`, `fsharp`, `dotnet`, `.net`
- **PHP**: `php`

### Examples

```bash
# Analyze a C++ project
python main.py /path/to/cpp/project cpp

# Analyze a C# project
python main.py /path/to/csharp/project csharp

# Analyze a PHP project
python main.py /path/to/php/project php
```

## Output Format

The tool generates two types of SBOM files for each package category found:

### JSON Format (`[category]_sbom.json`)
```json
{
  "components": [
    {
      "name": "package-name",
      "version": "1.0.0",
      "publisher": "vendor-name",
      "file": "/path/to/file",
      "type": "library"
    }
  ]
}
```

### CSV Format (`[category]_sbom.csv`)
```csv
Name,Version,Vendor,file,type
package-name,1.0.0,vendor-name,/path/to/file,library
```

## How It Works

1. **Language Detection**: The extractor determines the appropriate language-specific analyzer based on the provided language parameter

2. **Package Extraction**: Each language extractor scans the project directory for:
   - **C/C++**: Package manager files (`control`, `APKBUILD`, `PKGBUILD`, `*.spec`), build system files (`CMakeLists.txt`, `configure.ac`, `Makefile`, `meson.build`, `vcpkg.json`), and source files (`.c`, `.h`, `.hpp`, `.cpp`)
   - **.NET**: Binary files (`.dll`, `.unitypackage`), project files (`.csproj`, `.fsproj`, `manifest.json`), source files (`.cs`, `.csx`, `.fsx`), and package configs (`packages.config`, `paket.dependencies`)
   - **PHP**: Composer files (`composer.json`) and vendor directories, with fallback to vendor folder analysis

3. **AI-Powered Vendor Detection**: For each detected package, the following steps are performed:
    - **Web Search**: A web search is performed using DDGS to gather external context about the package
    - **LLM Processing**: The gathered context, along with the package name, is passed to a local LLM (e.g., Qwen:14B running via Ollama)
    - **Vendor Identification**: The model returns a likely vendor (e.g., "Google", "Apache", etc.)
    - **Output Cleaning**: The output is cleaned to remove prefixes like `vendor:`, quotes, and explanatory suffixes


4. **Filtering**: The system removes:
   - Duplicate packages (based on name, version, vendor, and type)
   - Standard library components (e.g., `stdio.h`, `string.h` for C/C++)

5. **SBOM Generation**: Creates both JSON and CSV formatted SBOM files organized by package categories

6. **Output**: Files are saved in a `result/[project_name]/` directory structure

## Key Components

### Extractor Class
- **Purpose**: Main orchestrator for the SBOM generation process
- **Responsibilities**: Language detection, package extraction coordination, deduplication, and output generation

### Language-Specific Extractors

#### C_CppExtractor
Handles C and C++ projects by parsing multiple file types:

**Package Manager Files:**
- `control` - Debian package control files
- `APKBUILD` - Alpine Linux package build files
- `PKGBUILD` - Arch Linux package build files
- `*.spec` - RPM package specification files

**Build System Files:**
- `CMakeLists.txt` - CMake build configuration
- `configure.ac` - Autotools configuration
- `Makefile` - Make build files (excluding `Makefile.in`)
- `meson.build` - Meson build system files
- `vcpkg.json` - vcpkg package manager manifests

**Source Files:**
- `.c`, `.h`, `.hpp`, `.cpp` - C/C++ source and header files

#### DotnetExtractor
Processes .NET ecosystem projects by parsing:

**Binary Files:**
- `.dll` - Dynamic Link Libraries
- `.unitypackage` - Unity package files

**Project Files:**
- `.csproj` - C# project files
- `.fsproj` - F# project files
- `manifest.json` - Package manifest files

**Source Files:**
- `.cs` - C# source files
- `.csx` - C# script files
- `.fsx` - F# script files

**Package Management Files:**
- `packages.config` - NuGet packages configuration
- `paket.dependencies` - Paket dependency management files

#### PhpExtractor
Analyzes PHP projects by scanning for:

**Package Management:**
- `composer.json` - Composer package definition files
- `vendor/` - Vendor directory containing installed packages

**Fallback Strategy:**
- If `composer.json` is found: Parses composer files for package dependencies
- If only `vendor/` folder exists: Analyzes installed packages in vendor directory
- If neither exists: Reports no packages found

### Standard Library Handling
- Maintains lists of standard libraries for each language
- Prevents system libraries from cluttering SBOM reports
- Focuses output on third-party and custom dependencies

## Error Handling

The tool includes comprehensive error handling for:
- Invalid file paths
- File encoding issues
- Permission problems
- Malformed project structures

Errors are logged to the console with descriptive messages.
