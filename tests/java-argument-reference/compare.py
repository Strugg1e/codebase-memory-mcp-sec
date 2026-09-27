"""Compare four fixed Java fixtures with bounded ordinary-argument queries.

Only the checked-in driver and demo-owned source templates are compiled/run.
The finite observations do not prove whole-program flow or control dependence.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "security"))
from demo_arguments import CASES, fixture_sources, run_case
from demo_flow import require, sha

EXPECTED = {
    "plain": ([100, 100, 101, 100, 101], {"tenant"}),
    "swapped": ([10, 11, 10, -1, -1], {"id"}),
    "overwritten": ([0, 0, 0, 0, 0], set()),
    "known_and_unknown": ([100, 100, 101, 777, 777], {"tenant"}),
}


def command(argv: list[str], cwd: Path) -> str:
    result = subprocess.run(argv, cwd=cwd, capture_output=True, encoding="utf-8", timeout=30)
    require(result.returncode == 0, f"reference_command_failed ({result.returncode}): {result.stderr[:2000]}")
    return result.stdout


def compare(binary: Path) -> dict:
    javac, java = shutil.which("javac"), shutil.which("java")
    require(javac is not None and java is not None, "javac_and_java_required")
    # Ignore external Java option/classpath injection; only the trusted fixture runs.
    unsafe = ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "CLASSPATH")
    require(not any(os.environ.get(key) for key in unsafe), "unset_external_java_options_for_reference")
    driver = Path(__file__).with_name("ArgumentReference.java").read_bytes()
    details = []
    with tempfile.TemporaryDirectory(prefix="cbm-java-arguments-") as tmp:
        for case in CASES:
            directory = Path(tmp) / case
            directory.mkdir()
            classes = directory / "classes"
            classes.mkdir()
            sources = fixture_sources(case)
            for name, source in sources.items():
                (directory / name).write_text(source, encoding="utf-8")
            (directory / "ArgumentReference.java").write_bytes(driver)
            command([javac, "-proc:none", "-encoding", "UTF-8", "-d", str(classes),
                     *[str(directory / name) for name in sorted(sources)],
                     str(directory / "ArgumentReference.java")], directory)
            outputs = [int(line) for line in command([java, "-cp", str(classes), "sample.ArgumentReference"], directory).splitlines()]
            expected_values, expected_origins = EXPECTED[case]
            require(outputs == expected_values, f"unexpected_runtime_values: {case}")
            static = run_case(binary, case)
            origins = {p["source"]["parameter"]["name"]["text_prefix"] for p in static["result"]["paths"]}
            require(origins == expected_origins, f"unexpected_static_origins: {case}")
            observed = {name for index, name in enumerate(("id", "tenant"), start=1) if outputs[index] != outputs[0]}
            require(observed <= origins, f"observed_data_change_missing: {case}")
            if case == "known_and_unknown":
                require("argument_origin_has_unknown_parts" in static["result"]["gaps"], "unknown_erased_by_runtime_sample")
            details.append({"case": case, "fixture_sha256": {n: sha(s.encode("utf-8")) for n, s in sources.items()},
                            "runtime_values": outputs, "observed_nonbranch_parameter_changes": sorted(observed),
                            "static_formal_origins": sorted(origins), "gaps": static["result"]["gaps"],
                            "source_references_checked": static["source_references_checked"]})
    return {"schema": "cbm.java-argument-reference.v1", "independent_fixture": True,
            "case_count": len(details), "runtime_evaluations": 5 * len(details),
            "only_repository_owned_java_executed": True, "business_target_execution": False,
            "program_relation_proof": False, "vulnerability_verdict": "not_evaluated",
            "comparison_scope": "finite_nonbranch_data_perturbations_not_control_dependence_or_all_paths",
            "driver_sha256": sha(driver), "results": details}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mcp", type=Path, required=True)
    args = parser.parse_args()
    try:
        binary = args.mcp.resolve(strict=True)
        require(binary.is_file() and os.access(binary, os.X_OK), "trusted_mcp_not_executable")
        print(json.dumps(compare(binary), ensure_ascii=False, indent=2))
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"reference_failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
