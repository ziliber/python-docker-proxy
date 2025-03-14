from contextlib import asynccontextmanager
import logging
import re
from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict
from aiohttp import ClientSession, ClientTimeout, web
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


@asynccontextmanager
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
        yield resp


def response_unauthorized(url: URL):
    headers = {
        "WWW-Authenticate": f'Bearer realm="{url.scheme}://{url.host_port_subcomponent}/v2/auth",service="docker-proxy"'
    }
    return web.json_response({"message": "UNAUTHORIZED"}, status=401, headers=headers)


async def handle_request(request: web.Request):
    url = request.url
    upstream = DockerHub
    scope = request.query.get("scope", "")
    path = url.path
    if url.parts[1] == "v2" and url.parts[2].find(".") != -1:
        upstream = "https://" + url.parts[2]
        path = "/v2/" + "/".join(url.parts[3:])
    if scope:
        scope_parts = scope.split(":")
        if len(scope_parts) == 3:
            s = scope_parts[1].split("/")
            if "." in s[0]:
                upstream = "https://" + s[0]
                del s[0]
                scope_parts[1] = "/".join(s)
                scope = ":".join(scope_parts)

    logger.info(f"Request: {url}, upstream: {upstream}")

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
            if scope and is_docker_hub:
                scope_parts = scope.split(":")
                if len(scope_parts) == 3 and "/" not in scope_parts[1]:
                    scope_parts[1] = f"library/{scope_parts[1]}"
                    scope = ":".join(scope_parts)
            async with fetch_token(
                www_authenticate, scope, authorization
            ) as token_resp:
                resp_data = await token_resp.read()
                return web.Response(
                    body=resp_data,
                    status=token_resp.status,
                    content_type=token_resp.content_type,
                )

    if is_docker_hub:
        path_parts = url.path.split("/")
        if len(path_parts) == 5:
            path_parts.insert(2, "library")
            redirect_url = url.with_path("/".join(path_parts))
            return web.HTTPMovedPermanently(location=str(redirect_url))

    new_url = f"{upstream}{path}"
    headers = request.headers.copy()
    del headers["Host"]
    resp = await session.request(request.method, new_url, headers=headers)
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

    return web.Response(body=resp.content, status=resp.status, headers=resp.headers)


async def main():
    global session
    session = ClientSession(
        proxy=settings.PROXY, timeout=ClientTimeout(total=10 * 60, sock_connect=30)
    )
    app = web.Application(client_max_size=100 << 20)
    app.router.add_routes([web.route("*", "/{path:.*}", handle_request)])
    logger.info(f"Server started at http://{settings.HOST}:{settings.PORT}")
    return app


if __name__ == "__main__":
    web.run_app(app=main(), host=settings.HOST, port=settings.PORT, access_log=None)
