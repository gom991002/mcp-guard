import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "mvp" / "02-remote-gateway-mcp"))
sys.path.insert(0, str(ROOT / "mvp" / "03-server-registration-config"))

from mcp_guard.registry import GuardRegistry  # noqa: E402
from server_registry.loader import (  # noqa: E402
    load_gateway_config,
    server_registry_from_dict,
)
from server_registry.validation import validate_server_registry  # noqa: E402


class ServerRegistrationMvpTests(unittest.TestCase):
    def test_loads_servers_json_into_gateway_config(self) -> None:
        policy = GuardRegistry.from_path(ROOT / "configs" / "example-policy.json")
        config = load_gateway_config(
            ROOT / "mvp" / "03-server-registration-config" / "configs" / "servers.json",
            policy,
        )

        self.assertEqual([upstream.name for upstream in config.upstreams], ["company-tools", "helper"])
        self.assertEqual(sorted(config.allowed_origins), ["https://chat.example"])
        self.assertEqual(
            [tool.name for tool in config.iter_tools()],
            ["company.search", "helper.summarize", "helper.risky"],
        )

    def test_rejects_server_not_registered_in_policy(self) -> None:
        registry_config = server_registry_from_dict(
            {
                "servers": [
                    {
                        "name": "unknown",
                        "namespace": "company",
                        "transport": "streamable_http",
                        "url": "https://unknown.example/mcp",
                        "tools": [],
                    }
                ]
            }
        )
        policy = GuardRegistry.from_path(ROOT / "configs" / "example-policy.json")

        with self.assertRaisesRegex(ValueError, "registered_servers"):
            validate_server_registry(registry_config, policy)

    def test_rejects_duplicate_tool_names_per_server(self) -> None:
        registry_config = server_registry_from_dict(
            {
                "servers": [
                    {
                        "name": "helper",
                        "namespace": "company",
                        "transport": "streamable_http",
                        "url": "https://helper.example/mcp",
                        "tools": [
                            {
                                "name": "helper.summarize",
                                "description": "A",
                                "input_schema": {},
                            },
                            {
                                "name": "helper.summarize",
                                "description": "B",
                                "input_schema": {},
                            },
                        ],
                    }
                ]
            }
        )
        policy = GuardRegistry.from_path(ROOT / "configs" / "example-policy.json")

        with self.assertRaisesRegex(ValueError, "duplicate tool"):
            validate_server_registry(registry_config, policy)

    def test_rejects_duplicate_tool_names_across_enabled_servers(self) -> None:
        registry_config = server_registry_from_dict(
            {
                "servers": [
                    {
                        "name": "company-tools",
                        "namespace": "company",
                        "transport": "streamable_http",
                        "url": "https://company.example/mcp",
                        "tools": [
                            {
                                "name": "shared.search",
                                "description": "A",
                                "input_schema": {},
                            }
                        ],
                    },
                    {
                        "name": "helper",
                        "namespace": "company",
                        "transport": "streamable_http",
                        "url": "https://helper.example/mcp",
                        "tools": [
                            {
                                "name": "shared.search",
                                "description": "B",
                                "input_schema": {},
                            }
                        ],
                    },
                ]
            }
        )
        policy = GuardRegistry.from_path(ROOT / "configs" / "example-policy.json")

        with self.assertRaisesRegex(ValueError, "duplicate exposed tool names"):
            validate_server_registry(registry_config, policy)

    def test_allows_duplicate_tool_names_on_disabled_servers(self) -> None:
        registry_config = server_registry_from_dict(
            {
                "servers": [
                    {
                        "name": "company-tools",
                        "namespace": "company",
                        "transport": "streamable_http",
                        "url": "https://company.example/mcp",
                        "tools": [
                            {
                                "name": "shared.search",
                                "description": "A",
                                "input_schema": {},
                            }
                        ],
                    },
                    {
                        "name": "helper",
                        "namespace": "company",
                        "transport": "streamable_http",
                        "url": "https://helper.example/mcp",
                        "enabled": False,
                        "tools": [
                            {
                                "name": "shared.search",
                                "description": "B",
                                "input_schema": {},
                            }
                        ],
                    },
                ]
            }
        )
        policy = GuardRegistry.from_path(ROOT / "configs" / "example-policy.json")

        validate_server_registry(registry_config, policy)

    def test_rejects_non_boolean_enabled_value(self) -> None:
        with self.assertRaisesRegex(ValueError, "enabled must be a boolean"):
            server_registry_from_dict(
                {
                    "servers": [
                        {
                            "name": "helper",
                            "namespace": "company",
                            "transport": "streamable_http",
                            "url": "https://helper.example/mcp",
                            "enabled": "false",
                            "tools": [],
                        }
                    ]
                }
            )


if __name__ == "__main__":
    unittest.main()

