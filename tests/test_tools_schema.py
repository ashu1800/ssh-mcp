"""Tool description contract and schema hygiene."""

from __future__ import annotations

import re

import pytest

from ssh_mcp.server import create_server

SNAKE_CASE = re.compile(r"^[a-z][a-z0-9]*(_[a-z0-9]+)*$")


@pytest.fixture
async def tools(settings):
    app = create_server(settings)
    return await app.list_tools()


@pytest.mark.asyncio
async def test_all_expected_tools_are_registered(tools):
    names = {tool.name for tool in tools}
    assert names == {
        # discovery / connection lifecycle
        "list_servers",
        "resolve_server",
        "connect",
        "disconnect",
        "get_connection_stats",
        # raw execution and transfers
        "execute_command",
        "upload_file",
        "download_file",
        "upload_files",
        "download_files",
        # remote filesystem
        "list_directory",
        "stat_file",
        "make_directory",
        "remove_path",
        "rename_path",
        "change_permissions",
        # semantic inspection: these exist so the model does not have to
        # assemble shell pipelines itself
        "get_service_status",
        "list_services",
        "tail_log",
        "get_disk_usage",
        "get_system_overview",
        "list_processes",
        "list_listening_ports",
    }


@pytest.mark.asyncio
async def test_tool_names_are_snake_case(tools):
    for tool in tools:
        assert SNAKE_CASE.match(tool.name), tool.name


@pytest.mark.asyncio
async def test_descriptions_are_substantial_and_guided(tools):
    for tool in tools:
        description = tool.description or ""
        assert len(description) >= 30, tool.name
        assert "Use when" in description, tool.name


@pytest.mark.asyncio
async def test_every_parameter_has_a_description(tools):
    missing = []
    for tool in tools:
        for prop, schema in (tool.input_schema.get("properties") or {}).items():
            if not schema.get("description"):
                missing.append(f"{tool.name}.{prop}")
    assert not missing, f"parameters without descriptions: {missing}"


@pytest.mark.asyncio
async def test_input_schema_requires_object_root(tools):
    for tool in tools:
        assert tool.input_schema.get("type") == "object", tool.name


@pytest.mark.asyncio
async def test_context_parameter_is_not_exposed(tools):
    for tool in tools:
        properties = tool.input_schema.get("properties") or {}
        assert "ctx" not in properties, tool.name
        assert "context" not in properties, tool.name
