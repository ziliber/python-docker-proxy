import logging
import re
from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict
from aiohttp import ClientSession, web
from yarl import URL


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_ignore_empty=True,
        extra="ignore",
        env_prefix="DP_",
    )

    lOGGER_LEVEL: str = "info"
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    PROXY: Optional[str] = None


settings = Settings()  # type: ignore


def str_to_log_level(level_str):
    level_mapping = logging.getLevelNamesMapping()
    level_str = level_str.upper()
    if level_str in level_mapping:
        return level_mapping[level_str]
    raise ValueError(f"Invalid log level string: {level_str}")


logger = logging.getLogger(__name__)
logging.basicConfig(
    level=str_to_log_level(settings.lOGGER_LEVEL),
    format="%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s",
)


DockerHub = "https://registry-1.docker.io"

routes = {
    # production
    "docker": DockerHub,
    "quay": "https://quay.io",
    "gcr": "https://gcr.io",
    "k8s-gcr": "https://k8s.gcr.io",
    "k8s": "https://registry.k8s.io",
    "ghcr": "https://ghcr.io",
    "cloudsmith": "https://docker.cloudsmith.io",
    "ecr": "https://public.ecr.aws",
    # staging
    "docker-staging": DockerHub,
}

session: ClientSession


def route_by_hosts(host):
    if host in routes:
        return routes[host]
    return DockerHub


def parseAuthenticate(authenticateStr):
    # sample: Bearer realm="https://auth.ipv6.docker.com/token",service="registry.docker.io"
    # match strings after =" and before "
    re_pattern = r'(?<==")(?:\\.|[^"\\])*(?=")'
    matches = re.findall(re_pattern, authenticateStr)
    if len(matches) < 2:
        raise ValueError(f"invalid Www-Authenticate Header: {authenticateStr}")
    return {
        "realm": matches[0],
        "service": matches[1],
    }


async def fetch_token(www_authenticate, scope, authorization):
    url = www_authenticate["realm"]
    params = {}
    if www_authenticate["service"]:
        params["service"] = www_authenticate["service"]
    if scope:
        params["scope"] = scope
    headers = {}
    if authorization:
        headers["Authorization"] = authorization
    async with session.get(url, params=params, headers=headers) as resp:
        return await resp.read()


def response_unauthorized(url: URL):
    headers = {
        "WWW-Authenticate": f'Bearer realm="{url.scheme}://{url.host_port_subcomponent}/v2/auth",service="docker-proxy"'
    }
    return web.json_response({"message": "UNAUTHORIZED"}, status=401, headers=headers)


async def handle_request(request: web.Request):
    url = request.url
    upstream = route_by_hosts(url.host.split(".")[0])  # type: ignore
    if upstream == "":
        return web.json_response({"routes": routes}, status=404)
    is_docker_hub = upstream == DockerHub
    authorization = request.headers.get("Authorization")

    if url.path == "/v2/":
        new_url = f"{upstream}/v2/"
        headers = {}
        if authorization:
            headers["Authorization"] = authorization
        async with session.get(new_url, headers=headers) as resp:
            if resp.status == 401:
                return response_unauthorized(url)
            return web.Response(
                body=await resp.read(), status=resp.status, headers=resp.headers
            )

    if url.path == "/v2/auth":
        new_url = f"{upstream}/v2/"
        async with session.get(new_url) as resp:
            if resp.status != 401:
                return web.Response(
                    body=await resp.read(), status=resp.status, headers=resp.headers
                )
            authenticate_str = resp.headers.get("WWW-Authenticate")
            if authenticate_str is None:
                return web.Response(
                    body=await resp.read(), status=resp.status, headers=resp.headers
                )
            www_authenticate = parseAuthenticate(authenticate_str)
            scope = request.query.get("scope")
            if scope and is_docker_hub:
                scopeParts = scope.split(":")
                if len(scopeParts) == 3 and "/" not in scopeParts[1]:
                    scopeParts[1] = f"library/{scopeParts[1]}"
                    scope = ":".join(scopeParts)
            token_resp = await fetch_token(www_authenticate, scope, authorization)
            return web.Response(body=token_resp)

    if is_docker_hub:
        path_parts = url.path.split("/")
        if len(path_parts) == 5:
            path_parts.insert(2, "library")
            redirect_url = url.with_path("/".join(path_parts))
            return web.HTTPMovedPermanently(location=str(redirect_url))

    new_url = f"{upstream}{url.path}"
    headers = request.headers.copy()
    del headers["Host"]
    async with session.request(request.method, new_url, headers=headers) as resp:
        if resp.status == 401:
            return response_unauthorized(url)
        if is_docker_hub and resp.status == 307 and "Location":
            location = resp.headers.get("Location")
            if location:
                async with session.get(location) as redirect_resp:
                    return web.Response(
                        body=await redirect_resp.read(),
                        status=redirect_resp.status,
                        headers=redirect_resp.headers,
                    )
        return web.Response(
            body=await resp.read(), status=resp.status, headers=resp.headers
        )


async def main():
    global session
    session = ClientSession(proxy=settings.PROXY)
    app = web.Application()
    app.router.add_routes([web.route("*", "/{path:.*}", handle_request)])
    logger.info(f"Server started at http://{settings.HOST}:{settings.PORT}")
    return app


if __name__ == "__main__":
    web.run_app(app=main(), host=settings.HOST, port=settings.PORT)
