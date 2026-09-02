import json
from pathlib import Path

from jsonschema import Draft7Validator

from report_generator.validation import CURRENT_SCHEMA_VERSION, validate_scan_report


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = REPOSITORY_ROOT / "docs" / "schema" / "scan-result-v1.json"
EXAMPLE_PATHS = [
    REPOSITORY_ROOT / "docs" / "example-scan.json",
    *sorted((REPOSITORY_ROOT / "testdata" / "samples").glob("*-scan.json")),
]


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_schema_is_valid_and_matches_python_consumer():
    schema = load_json(SCHEMA_PATH)

    Draft7Validator.check_schema(schema)
    assert schema["properties"]["schema_version"]["const"] == CURRENT_SCHEMA_VERSION


def test_all_versioned_examples_match_the_canonical_contract():
    validator = Draft7Validator(load_json(SCHEMA_PATH))

    assert EXAMPLE_PATHS
    for example_path in EXAMPLE_PATHS:
        report = load_json(example_path)
        errors = sorted(validator.iter_errors(report), key=lambda error: list(error.path))
        assert not errors, f"{example_path}: {[error.message for error in errors]}"
        validate_scan_report(report)
