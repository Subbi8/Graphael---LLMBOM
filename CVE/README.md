# gauntlet-sbom-version-advisor

## Overview
This project uses `pre-commit` hooks to ensure code quality and security by running tools like Ruff and Bandit before every commit.

## Prerequisites
- Python 3.10 or higher
- [pip](https://pip.pypa.io/en/stable/)
- [pre-commit](https://pre-commit.com/)

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Gauntlet-PESU-Projects/Gauntlet-Secretes-Validator.git
   cd Gauntlet-Secretes-Validator
   ```

2. **Install required Python packages:**
   ```bash
   pip install ruff bandit pre-commit
   ```

3. **Install pre-commit hooks:**
   ```bash
   pre-commit install
   ```
   This will set up the hooks defined in `.pre-commit-config.yaml` to run automatically on `git commit`.

4. **(Optional) Run all hooks on all files:**
   ```bash
   pre-commit run --all-files
   ```

## Configuration
- Linting and formatting are configured in `pyproject.toml`.
- Security checks are configured for Bandit in the same file.

## References
- [pre-commit documentation](https://pre-commit.com/)
- [Ruff documentation](https://docs.astral.sh/ruff/)
- [Bandit documentation](https://bandit.readthedocs.io/en/latest/)

---