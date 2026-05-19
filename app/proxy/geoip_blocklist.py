from __future__ import annotations

import subprocess
from pathlib import Path

from flask import current_app

COUNTRY_NAMES: dict[str, str] = {
    "AD": "Andorra", "AE": "Emiratos Árabes Unidos", "AF": "Afganistán",
    "AG": "Antigua y Barbuda", "AL": "Albania", "AM": "Armenia",
    "AO": "Angola", "AR": "Argentina", "AT": "Austria", "AU": "Australia",
    "AZ": "Azerbaiyán", "BA": "Bosnia y Herzegovina", "BD": "Bangladés",
    "BE": "Bélgica", "BF": "Burkina Faso", "BG": "Bulgaria",
    "BH": "Baréin", "BI": "Burundi", "BJ": "Benín", "BN": "Brunéi",
    "BO": "Bolivia", "BR": "Brasil", "BS": "Bahamas", "BT": "Bután",
    "BW": "Botsuana", "BY": "Bielorrusia", "BZ": "Belice",
    "CA": "Canadá", "CD": "Congo (RDC)", "CF": "Rep. Centroafricana",
    "CG": "Congo", "CH": "Suiza", "CI": "Costa de Marfil", "CL": "Chile",
    "CM": "Camerún", "CN": "China", "CO": "Colombia", "CR": "Costa Rica",
    "CU": "Cuba", "CV": "Cabo Verde", "CY": "Chipre", "CZ": "Chequia",
    "DE": "Alemania", "DJ": "Yibuti", "DK": "Dinamarca",
    "DO": "República Dominicana", "DZ": "Argelia",
    "EC": "Ecuador", "EE": "Estonia", "EG": "Egipto", "ER": "Eritrea",
    "ES": "España", "ET": "Etiopía", "FI": "Finlandia", "FJ": "Fiyi",
    "FR": "Francia", "GA": "Gabón", "GB": "Reino Unido", "GE": "Georgia",
    "GH": "Ghana", "GM": "Gambia", "GN": "Guinea", "GQ": "Guinea Ecuatorial",
    "GR": "Grecia", "GT": "Guatemala", "GW": "Guinea-Bisáu", "GY": "Guyana",
    "HN": "Honduras", "HR": "Croacia", "HT": "Haití", "HU": "Hungría",
    "ID": "Indonesia", "IE": "Irlanda", "IL": "Israel", "IN": "India",
    "IQ": "Irak", "IR": "Irán", "IS": "Islandia", "IT": "Italia",
    "JM": "Jamaica", "JO": "Jordania", "JP": "Japón",
    "KE": "Kenia", "KG": "Kirguistán", "KH": "Camboya", "KI": "Kiribati",
    "KM": "Comoras", "KN": "San Cristóbal y Nieves", "KP": "Corea del Norte",
    "KR": "Corea del Sur", "KW": "Kuwait", "KZ": "Kazajistán",
    "LA": "Laos", "LB": "Líbano", "LC": "Santa Lucía", "LI": "Liechtenstein",
    "LK": "Sri Lanka", "LR": "Liberia", "LS": "Lesoto", "LT": "Lituania",
    "LU": "Luxemburgo", "LV": "Letonia", "LY": "Libia",
    "MA": "Marruecos", "MC": "Mónaco", "MD": "Moldavia", "ME": "Montenegro",
    "MG": "Madagascar", "MK": "Macedonia del Norte", "ML": "Mali",
    "MM": "Myanmar", "MN": "Mongolia", "MR": "Mauritania", "MT": "Malta",
    "MU": "Mauricio", "MV": "Maldivas", "MW": "Malaui", "MX": "México",
    "MY": "Malasia", "MZ": "Mozambique", "NA": "Namibia", "NE": "Níger",
    "NG": "Nigeria", "NI": "Nicaragua", "NL": "Países Bajos",
    "NO": "Noruega", "NP": "Nepal", "NR": "Nauru", "NZ": "Nueva Zelanda",
    "OM": "Omán", "PA": "Panamá", "PE": "Perú", "PG": "Papúa Nueva Guinea",
    "PH": "Filipinas", "PK": "Pakistán", "PL": "Polonia",
    "PT": "Portugal", "PW": "Palaos", "PY": "Paraguay",
    "QA": "Catar", "RO": "Rumanía", "RS": "Serbia", "RU": "Rusia",
    "RW": "Ruanda", "SA": "Arabia Saudita", "SB": "Islas Salomón",
    "SC": "Seychelles", "SD": "Sudán", "SE": "Suecia", "SG": "Singapur",
    "SI": "Eslovenia", "SK": "Eslovaquia", "SL": "Sierra Leona",
    "SM": "San Marino", "SN": "Senegal", "SO": "Somalia", "SR": "Surinam",
    "SS": "Sudán del Sur", "ST": "Santo Tomé y Príncipe", "SV": "El Salvador",
    "SY": "Siria", "SZ": "Esuatini", "TD": "Chad", "TG": "Togo",
    "TH": "Tailandia", "TJ": "Tayikistán", "TL": "Timor Oriental",
    "TM": "Turkmenistán", "TN": "Túnez", "TO": "Tonga", "TR": "Turquía",
    "TT": "Trinidad y Tobago", "TV": "Tuvalu", "TZ": "Tanzania",
    "UA": "Ucrania", "UG": "Uganda", "US": "Estados Unidos", "UY": "Uruguay",
    "UZ": "Uzbekistán", "VA": "Ciudad del Vaticano", "VC": "San Vicente",
    "VE": "Venezuela", "VN": "Vietnam", "VU": "Vanuatu",
    "WS": "Samoa", "YE": "Yemen", "ZA": "Sudáfrica", "ZM": "Zambia",
    "ZW": "Zimbabue",
}


def write_blocklist_conf() -> Path:
    """Write 10-blocklist.conf from GeoBlocklistEntry table and return the path."""
    from app.models import GeoBlocklistEntry

    output_dir = Path(current_app.config["PROXY_CONFIG_DIR"])
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "10-blocklist.map"

    entries = GeoBlocklistEntry.query.filter_by(enabled=True).all()
    lines = ["# WardNode GeoIP country blocklist — generated automatically. Do not edit.\n"]
    for entry in entries:
        lines.append(f"{entry.country_code} 1;  # {entry.country_name}\n")

    path.write_text("".join(lines), encoding="utf-8")
    return path


def reload_nginx() -> tuple[bool, str]:
    """Test nginx config then send reload signal to the proxy container via Docker SDK."""
    container_name = current_app.config.get("NGINX_CONTAINER_NAME", "wardnode-proxy")
    try:
        import docker as docker_sdk
        client = docker_sdk.from_env()
        container = client.containers.get(container_name)
        test = container.exec_run("nginx -t")
        if test.exit_code != 0:
            return False, test.output.decode("utf-8", errors="replace").strip()
        result = container.exec_run("nginx -s reload")
        if result.exit_code == 0:
            return True, ""
        return False, result.output.decode("utf-8", errors="replace").strip()
    except Exception as exc:
        return False, str(exc)
