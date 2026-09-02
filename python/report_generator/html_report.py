import base64
import os
from functools import lru_cache

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .models import ScanReport
from .aggregation import aggregate_report
from .chart import build_chart

_PACKAGE_DIR = os.path.dirname(__file__)
_FONT_DIR = os.path.join(_PACKAGE_DIR, "fonts")
_ASSET_DIR = os.path.join(_PACKAGE_DIR, "assets")

# The report must render identically offline, inside a CI artifact viewer and
# on GitHub Pages, so every asset is embedded rather than fetched.
_EMBEDDED_FONTS = {
    "archivo_narrow": ("archivo-narrow.woff2", "font/woff2"),
    "sometype_mono": ("sometype-mono.woff2", "font/woff2"),
}
_EMBEDDED_IMAGES = {
    "paper_ground": ("paper-ground.png", "image/png"),
    "stamp_ink": ("stamp-ink.png", "image/png"),
}


@lru_cache(maxsize=None)
def _data_uri(path: str, mime: str) -> str:
    with open(path, "rb") as handle:
        encoded = base64.b64encode(handle.read()).decode("ascii")
    return f"data:{mime};base64,{encoded}"


def _embedded_assets() -> dict:
    assets = {}
    for key, (filename, mime) in _EMBEDDED_FONTS.items():
        assets[key] = _data_uri(os.path.join(_FONT_DIR, filename), mime)
    for key, (filename, mime) in _EMBEDDED_IMAGES.items():
        assets[key] = _data_uri(os.path.join(_ASSET_DIR, filename), mime)
    return assets


def generate_html_report(report: ScanReport) -> str:
    template_dir = os.path.join(_PACKAGE_DIR, "templates")
    env = Environment(
        loader=FileSystemLoader(template_dir),
        autoescape=select_autoescape(["html", "xml", "j2"]),
    )

    template = env.get_template("report.html.j2")
    aggregated_data = aggregate_report(report)
    aggregated_data["chart"] = build_chart(
        aggregated_data["findings"], aggregated_data["affected_files"]
    )
    aggregated_data["assets"] = _embedded_assets()

    return template.render(**aggregated_data)


def write_html_report(report: ScanReport, output_path: str) -> None:
    html_content = generate_html_report(report)
    output_dir = os.path.dirname(output_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
