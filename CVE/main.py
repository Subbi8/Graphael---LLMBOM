#!/usr/bin/env python3
"""
CVE Optimization Pipeline Main Script

This module orchestrates the complete CVE optimization pipeline by running
the first optimal analysis followed by recursive optimization.

Files in pipeline:
1. first_optimal_july.py - Initial optimal version analysis
2. recursive_july.py - Recursive optimization with GitHub validation
3. exploit_fix.py - Exploit detection (called by other scripts)
4. github_validation_july.py - GitHub validation (called by other scripts)
"""

import subprocess  # nosec B404 - subprocess needed for pipeline orchestration with validated inputs
import sys
from pathlib import Path

# Constants
PIPELINE_TIMEOUT = 7200  # 2 hours timeout
SCRIPT_EXTENSION = '.py'
REQUIRED_SCRIPTS = ['first_optimal_july.py', 'recursive_july.py']
DEPENDENCY_SCRIPTS = ['exploit_fix.py', 'github_validation_july.py']


class ScriptValidator:
    """Validates script files and dependencies."""

    def __init__(self):
        """Initialize the script validator."""
        self.current_dir = Path.cwd()

    def validate_script_exists(self, script_name: str) -> bool:
        """
        Validate that a script file exists and is a Python file.

        Args:
            script_name: Name of the script to validate

        Returns:
            True if script exists and is valid, False otherwise
        """
        script_path = self.current_dir / script_name

        if not script_path.exists():
            print(f"Error: Script '{script_name}' not found in current directory")
            return False

        if not script_name.endswith(SCRIPT_EXTENSION):
            print(f"Error: '{script_name}' is not a Python file")
            return False

        return True

    def validate_all_scripts(self, required_scripts: list[str],
                           dependency_scripts: list[str]) -> bool:
        """
        Validate that all required and dependency scripts exist.

        Args:
            required_scripts: List of required pipeline scripts
            dependency_scripts: List of dependency scripts

        Returns:
            True if all scripts exist, False otherwise
        """
        print("Validating pipeline scripts...")

        # Check required scripts
        for script in required_scripts:
            if not self.validate_script_exists(script):
                return False

        # Check dependency scripts (warn if missing but don't fail)
        for script in dependency_scripts:
            if not self.validate_script_exists(script):
                print(f"Warning: Dependency script '{script}' not found")
                print("Some features may be disabled in the pipeline")

        print("Script validation completed successfully")
        return True


class ScriptRunner:
    """Handles secure execution of pipeline scripts."""

    def __init__(self):
        """Initialize the script runner."""
        self.python_executable = sys.executable

    def run_script(self, script_name: str) -> tuple[bool, str, str]:
        """
        Run a Python script safely with comprehensive error handling.

        Args:
            script_name: Name of the script to run

        Returns:
            Tuple of (success: bool, stdout: str, stderr: str)
        """
        script_path = Path(script_name).resolve()

        try:
            print(f"Executing: {script_name}")
            print("-" * 50)

            # Use subprocess.run with explicit arguments (no shell=True)
            result = subprocess.run(  # nosec B603 - inputs validated, no shell, explicit args
                [self.python_executable, str(script_path)],
                check=True,
                capture_output=True,
                text=True,
                timeout=PIPELINE_TIMEOUT,
                cwd=Path.cwd()
            )

            return True, result.stdout, result.stderr

        except subprocess.CalledProcessError as e:
            error_msg = (
                f"Process failed with exit code {e.returncode}\n"
                f"Error output: {e.stderr if e.stderr else 'No error output'}"
            )
            return False, e.stdout if e.stdout else "", error_msg

        except subprocess.TimeoutExpired:
            error_msg = f"Script timed out after {PIPELINE_TIMEOUT} seconds"
            return False, "", error_msg

        except FileNotFoundError:
            error_msg = f"Python interpreter not found at {self.python_executable}"
            return False, "", error_msg

        except Exception as e:
            error_msg = f"Unexpected error: {str(e)}"
            return False, "", error_msg

    def print_script_output(self, script_name: str, stdout: str, stderr: str):
        """
        Print script output in a formatted way.

        Args:
            script_name: Name of the script that was run
            stdout: Standard output from the script
            stderr: Standard error from the script
        """
        if stdout:
            print(f"Output from {script_name}:")
            print(stdout)

        if stderr:
            print(f"Warnings from {script_name}:")
            print(stderr)


class PipelineOrchestrator:
    """Orchestrates the complete CVE optimization pipeline."""

    def __init__(self):
        """Initialize the pipeline orchestrator."""
        self.validator = ScriptValidator()
        self.runner = ScriptRunner()
        self.pipeline_steps = [
            ('first_optimal_july.py', 'First optimal analysis'),
            ('recursive_july.py', 'Recursive optimization')
        ]

    def validate_environment(self) -> bool:
        """
        Validate the pipeline environment before execution.

        Returns:
            True if environment is valid, False otherwise
        """
        return self.validator.validate_all_scripts(
            REQUIRED_SCRIPTS, DEPENDENCY_SCRIPTS
        )

    def execute_pipeline_step(self, script_name: str,
                            description: str) -> bool:
        """
        Execute a single pipeline step.

        Args:
            script_name: Name of the script to execute
            description: Human-readable description of the step

        Returns:
            True if step completed successfully, False otherwise
        """
        print(f"\nExecuting: {description}")
        print("=" * 60)

        success, stdout, stderr = self.runner.run_script(script_name)

        if success:
            print(f"✓ {description} completed successfully")
            self.runner.print_script_output(script_name, stdout, stderr)
            return True
        else:
            print(f"✗ {description} failed")
            print(f"Error details: {stderr}")
            if stdout:
                print(f"Partial output: {stdout}")
            return False

    def run_pipeline(self) -> bool:
        """
        Execute the complete CVE optimization pipeline.

        Returns:
            True if pipeline completed successfully, False otherwise
        """
        print("CVE Optimization Pipeline")
        print("=" * 60)
        print("Pipeline components:")
        print("1. first_optimal_july.py - Initial optimal version analysis")
        print("2. recursive_july.py - Recursive optimization with GitHub validation")
        print("Dependencies:")
        print("- exploit_fix.py - Exploit detection module")
        print("- github_validation_july.py - GitHub validation module")
        print("=" * 60)

        # Validate environment
        if not self.validate_environment():
            print("Pipeline validation failed. Exiting.")
            return False

        # Execute pipeline steps
        for step_number, (script_name, description) in enumerate(self.pipeline_steps, 1):
            step_description = f"Step {step_number}: {description}"

            if not self.execute_pipeline_step(script_name, step_description):
                print(f"\nPipeline failed at step {step_number}")
                return False

        return True

    def print_completion_summary(self):
        """Print pipeline completion summary."""
        print("\n" + "=" * 60)
        print("CVE OPTIMIZATION PIPELINE COMPLETED SUCCESSFULLY!")
        print("=" * 60)
        print("Generated files:")
        print("- first_optimal_july.json (initial optimal versions)")
        print("- output_july.json (final recommendations)")
        print("- Detailed statistics and reports")
        print("\nPipeline Summary:")
        print("✓ Initial optimal version analysis completed")
        print("✓ Recursive optimization with GitHub validation completed")
        print("✓ Exploit detection integrated")
        print("✓ All output files generated successfully")
        print("=" * 60)


def main():
    """
    Main function to execute the CVE optimization pipeline.

    Returns:
        True if pipeline completed successfully, False otherwise
    """
    try:
        orchestrator = PipelineOrchestrator()

        if orchestrator.run_pipeline():
            orchestrator.print_completion_summary()
            return True
        else:
            print("\nPipeline execution failed. Check error messages above.")
            return False

    except KeyboardInterrupt:
        print("\nPipeline interrupted by user")
        return False

    except Exception as e:
        print(f"\nUnexpected error in pipeline: {e}")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)