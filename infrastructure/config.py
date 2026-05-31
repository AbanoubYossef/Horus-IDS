"""Centralised application settings loaded from environment / .env file."""

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """HORUS SOC configuration (env prefix: HORUS_)."""

    host: str = "127.0.0.1"
    port: int = 8000
    api_key: str = ""
    cors_origins: str = "*"
    db_path: Path = Path("./horus_soc.db")
    model_dir: Path = Path("./models")

    # Groq (no HORUS_ prefix)
    groq_api_key: str = Field(default="", validation_alias="GROQ_API_KEY")
    groq_model: str = Field(
        default="llama-3.1-8b-instant", validation_alias="GROQ_MODEL"
    )
    groq_api_url: str = "https://api.groq.com/openai/v1/chat/completions"

    @property
    def cors_origins_list(self) -> list[str]:
        """Return *cors_origins* split by comma into a list."""
        return [origin.strip() for origin in self.cors_origins.split(",")]

    model_config = {
        "env_prefix": "HORUS_",
        "env_file": ".env",
    }
