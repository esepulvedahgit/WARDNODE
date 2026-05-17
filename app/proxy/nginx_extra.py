import shutil
import subprocess
import tempfile
from pathlib import Path

from app.extensions import db
from app.models import NginxExtraConfig, Site


MAX_SNIPPET_LENGTH = 8000
DISALLOWED_DIRECTIVES = {
    "include",
    "load_module",
    "daemon",
    "master_process",
    "pid",
    "user",
    "worker_processes",
    "events",
    "http",
    "server",
    "location",
    "upstream",
    "map",
    "geo",
    "root",
    "alias",
    "ssl_certificate_key",
}


def ensure_site_nginx_extra_config(site: Site) -> NginxExtraConfig:
    if site.nginx_extra_config is None:
        config = NginxExtraConfig(site=site)
        db.session.add(config)
        db.session.commit()
    return site.nginx_extra_config


def validate_nginx_extra_config(server_snippet: str, location_snippet: str) -> list[str]:
    errors = []
    errors.extend(_validate_snippet_lines(server_snippet, "server"))
    errors.extend(_validate_snippet_lines(location_snippet, "location"))
    if errors:
        return errors

    nginx = shutil.which("nginx")
    if nginx is None:
        return []

    return _validate_with_nginx_binary(nginx, server_snippet, location_snippet)


def _validate_snippet_lines(snippet: str, context: str) -> list[str]:
    errors = []
    if len(snippet) > MAX_SNIPPET_LENGTH:
        errors.append(f"El bloque {context} excede {MAX_SNIPPET_LENGTH} caracteres.")
        return errors

    for line_number, raw_line in enumerate(snippet.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if any(char in line for char in "{}"):
            errors.append(f"{context}:{line_number} no permite bloques con llaves.")
            continue
        if not line.endswith(";"):
            errors.append(f"{context}:{line_number} debe terminar con punto y coma.")
            continue
        if any(ord(char) < 32 and char != "\t" for char in raw_line):
            errors.append(f"{context}:{line_number} contiene caracteres de control.")
            continue

        directive = line[:-1].split(maxsplit=1)[0]
        if not directive.replace("_", "").isalnum():
            errors.append(f"{context}:{line_number} tiene directiva invalida.")
        if directive in DISALLOWED_DIRECTIVES:
            errors.append(f"{context}:{line_number} usa directiva no permitida: {directive}.")
        if line.count('"') % 2 != 0 or line.count("'") % 2 != 0:
            errors.append(f"{context}:{line_number} tiene comillas desbalanceadas.")

    return errors


def _validate_with_nginx_binary(
    nginx: str,
    server_snippet: str,
    location_snippet: str,
) -> list[str]:
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        conf_path = temp_path / "nginx.conf"
        conf_path.write_text(
            f"""
events {{}}
http {{
    server {{
        listen 127.0.0.1:8088;
{_indent(server_snippet, 8)}
        location / {{
{_indent(location_snippet, 12)}
            proxy_pass http://127.0.0.1:65535;
        }}
    }}
}}
""",
            encoding="utf-8",
        )
        result = subprocess.run(
            [nginx, "-t", "-c", str(conf_path), "-p", str(temp_path)],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
    if result.returncode == 0:
        return []

    output = (result.stderr or result.stdout).strip()
    return [f"nginx -t fallo: {output.splitlines()[-1] if output else 'configuracion invalida'}"]


def _indent(snippet: str, spaces: int) -> str:
    prefix = " " * spaces
    return "\n".join(prefix + line if line.strip() else "" for line in snippet.splitlines())
