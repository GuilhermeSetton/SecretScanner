import os
from jinja2 import Environment, FileSystemLoader, select_autoescape

from .models import ScanReport
from .aggregation import aggregate_report


def generate_html_report(report: ScanReport) -> str:
    template_dir = os.path.join(os.path.dirname(__file__), "templates")
    env = Environment(
        loader=FileSystemLoader(template_dir),
        autoescape=select_autoescape(["html", "xml", "j2"]),
    )

    template = env.get_template("report.html.j2")
    aggregated_data = aggregate_report(report)

    return template.render(**aggregated_data)


def write_html_report(report: ScanReport, output_path: str) -> None:
    html_content = generate_html_report(report)
    output_dir = os.path.dirname(output_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
