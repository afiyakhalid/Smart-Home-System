from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    database_url: str = "postgresql+psycopg2://smarthome:smarthome@localhost:5432/smarthome"

    jwt_secret: str = "CHANGE_ME_DEV_SECRET"
    jwt_algorithm: str = "HS256"
    access_token_exp_minutes: int = 60

    mqtt_host: str = "localhost"
    mqtt_port: int = 1883

    cors_origins: str = "http://localhost:5173"

    guest_allowed_start_hour: int = 8
    guest_allowed_end_hour: int = 22

    ids_failed_login_threshold: int = 5
    ids_failed_login_window_seconds: int = 120
    ids_device_flood_threshold_per_min: int = 60
    ids_unlock_without_motion_window_seconds: int = 300


settings = Settings()