import os
from pathlib import Path
from pydantic_settings import BaseSettings
from typing import Optional

BASE_DIR = Path(__file__).resolve().parent.parent.parent


class Settings(BaseSettings):
    APP_NAME: str = "NPM Shield AI"
    APP_VERSION: str = "1.0.0"
    API_PREFIX: str = "/api"
    DEBUG: bool = True
    
    # Database
    DATABASE_URL: str = f"sqlite:///{BASE_DIR / 'npm_shield.db'}"
    
    # NPM Registry
    NPM_REGISTRY_URL: str = "https://registry.npmjs.org"
    OSV_API_URL: str = "https://api.osv.dev/v1/query"
    REQUEST_TIMEOUT: int = 20
    
    # AI / LLM Integration (optional)
    GEMINI_API_KEY: Optional[str] = os.getenv("GEMINI_API_KEY")
    OPENAI_API_KEY: Optional[str] = os.getenv("OPENAI_API_KEY")
    LLM_PROVIDER: str = os.getenv("LLM_PROVIDER", "deterministic") # "gemini", "openai", or "deterministic"
    
    # Demo Mode
    DEMO_MODE_ENABLED: bool = True
    
    # Sandboxing & Dynamic Analysis
    ENABLE_DYNAMIC_ANALYSIS: bool = False # Secure isolation disabled on Windows host
    
    model_config = {"env_file": ".env", "extra": "allow"}


settings = Settings()
