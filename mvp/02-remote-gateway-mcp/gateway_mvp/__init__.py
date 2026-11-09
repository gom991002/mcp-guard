"""Remote MCP gateway MVP prototype."""

__all__ = [
    "GatewayConfig",
    "GatewayResponse",
    "RemoteMcpGateway",
    "ToolDefinition",
    "UpstreamServer",
    "sample_gateway_config",
]


def __getattr__(name: str):
    if name == "sample_gateway_config":
        from .catalog import sample_gateway_config

        return sample_gateway_config
    if name == "RemoteMcpGateway":
        from .gateway import RemoteMcpGateway

        return RemoteMcpGateway
    if name in {"GatewayConfig", "GatewayResponse", "ToolDefinition", "UpstreamServer"}:
        from . import models

        return getattr(models, name)
    raise AttributeError(name)

