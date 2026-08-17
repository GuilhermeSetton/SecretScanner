import argparse
import json
import os
import sys

from .aggregation import aggregate_report
from .html_report import write_html_report
from .validation import ValidationError, load_and_validate_file


def parse_args(args=None):
    parser = argparse.ArgumentParser(
        prog="report_generator",
        description="Interpret and generate HTML/JSON reports from SecretScanner-K8s scan results",
    )
    parser.add_argument(
        "--input",
        "-i",
        required=True,
        help="Path to input scan result JSON file produced by SecretScanner-K8s",
    )
    parser.add_argument(
        "--output",
        "-o",
        required=True,
        help="Path to output file for report generation",
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["html", "json"],
        required=True,
        help="Report output format: 'html' or 'json'",
    )
    return parser.parse_args(args)


def run_cli(args=None) -> int:
    parsed_args = parse_args(args)

    try:
        report = load_and_validate_file(parsed_args.input)

        if parsed_args.format == "html":
            write_html_report(report, parsed_args.output)
        elif parsed_args.format == "json":
            aggregated = aggregate_report(report)
            output_dir = os.path.dirname(parsed_args.output)
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)
            with open(parsed_args.output, "w", encoding="utf-8") as f:
                json.dump(aggregated, f, indent=2)

        return 0

    except ValidationError as e:
        sys.stderr.write(f"Validation Error: {e}\n")
        return 1
    except Exception as e:
        sys.stderr.write(f"Execution Error: {e}\n")
        return 1


def main():
    sys.exit(run_cli())


if __name__ == "__main__":
    main()
