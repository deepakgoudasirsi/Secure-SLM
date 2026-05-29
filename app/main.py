from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from app.api.routes import alerts, analysis, auth, evaluation, health, logs
from app.config import get_settings
from app.db.database import init_db
from app.startup import seed_admin_user


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    seed_admin_user()
    Path(get_settings().upload_dir).mkdir(parents=True, exist_ok=True)
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title=settings.app_name,
        description="Lightweight Secure SLM for network threat detection and security log analysis",
        version="0.1.0",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    prefix = settings.api_prefix
    app.include_router(health.router)
    app.include_router(auth.router, prefix=prefix)
    app.include_router(logs.router, prefix=prefix)
    app.include_router(analysis.router, prefix=prefix)
    app.include_router(alerts.router, prefix=prefix)
    app.include_router(evaluation.router, prefix=prefix)

    static_dir = Path(__file__).parent / "static"
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=static_dir), name="static")

    @app.get("/", response_class=HTMLResponse)
    def dashboard():
        index = static_dir / "index.html"
        if index.exists():
            return index.read_text(encoding="utf-8")
        return "<h1>Secure-SLM API</h1><p>See /docs for API documentation.</p>"

    return app


app = create_app()
