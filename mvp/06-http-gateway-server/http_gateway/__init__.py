from .adapter import HttpGatewayAdapter
from .models import HttpRequest, HttpResponse


def __getattr__(name: str):
    if name == "build_server":
        from .server import build_server
        return build_server
    raise AttributeError(name)

__all__ = ["HttpGatewayAdapter", "HttpRequest", "HttpResponse", "build_server"]

