from pydantic_settings import BaseSettings, SettingsConfigDict
class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    database_url: str = "sqlite:///./tracepost.db"
    intel_enabled: bool = True
    ipinfo_token: str = ""
    secret_key: str = "dev"
settings = Settings()
