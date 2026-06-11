"""Interfaz común de proveedores LLM del SOC."""


class LLMError(Exception):
    """Fallo de un proveedor LLM (red, cuota, parsing). Nunca incluye la API key."""


class LLMProvider:
    name: str = "base"

    def __init__(self, api_key: str, model: str):
        self.api_key = api_key
        self.model = model

    def chat(self, system: str, user: str, *, json_mode: bool = True) -> tuple[str, int, int]:
        """Retorna (texto, tokens_in, tokens_out). Lanza LLMError ante fallo.

        json_mode=True  → el proveedor instruye al modelo a devolver JSON puro
                          (usado por analyze_incident).
        json_mode=False → prosa libre, sin forzar mime-type ni response_format
                          (usado por generate_llm_summary del reporte diario).
        """
        raise NotImplementedError
