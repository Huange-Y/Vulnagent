from __future__ import annotations

import struct
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from vulnagent.tools.registry import ToolRegistry
from vulnagent.tools.vuln_tools import register_all_vuln_tools


def test_artifact_first_tools_are_registered() -> None:
    registry = ToolRegistry()
    register_all_vuln_tools(registry)
    for tool_name in (
        "file_identify",
        "readelf_headers",
        "strings_extract",
        "binwalk_scan",
        "firmware_extract_summary",
        "firmware_read_path",
        "firmware_search",
        "firmware_web_surface_map",
        "firmware_extract_rootfs",
        "firmware_runtime_manifest",
        "firmware_service_inventory",
        "firmware_emulation_prepare",
        "firmware_emulation_launch_user",
        "firmware_emulation_probe",
        "firmware_emulation_launch_system",
    ):
        assert tool_name in registry


def test_exploit_support_tools_are_registered() -> None:
    registry = ToolRegistry()
    register_all_vuln_tools(registry)
    for tool_name in ("searchsploit", "netcat_connect"):
        assert tool_name in registry


def test_runtime_workspace_manager_uses_settings_run_root(monkeypatch, tmp_path: Path) -> None:
    import vulnagent.tools.vuln_tools as vuln_tools

    class FakeSettings:
        def get(self, key: str, default=None):
            if key == "runtime.run_root":
                return str(tmp_path / "runs-root")
            return default

    class FakeSettingsManager:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def load(self):
            return FakeSettings()

    monkeypatch.setattr(vuln_tools, "SettingsManager", FakeSettingsManager, raising=False)

    manager = vuln_tools._runtime_workspace_manager()

    assert manager.base_root == (tmp_path / "runs-root")


def test_firmware_emulation_prepare_uses_bound_runtime_run_id(monkeypatch, tmp_path: Path) -> None:
    import vulnagent.tools.vuln_tools as vuln_tools
    from vulnagent.runtime.context import bind_runtime_run_id

    artifact = tmp_path / "firmware.img"
    artifact.write_bytes(b"demo")
    rootfs = tmp_path / "rootfs"
    (rootfs / "bin").mkdir(parents=True)
    (rootfs / "bin" / "busybox").write_bytes(b"\x7fELF" + b"\x01" * 128)

    class FakeExtractor:
        def build_manifest(self, _artifact, workspace):
            return SimpleNamespace(
                rootfs_path=rootfs,
                architecture="mips",
                endianness="little",
                workspace_root=workspace.root,
                warnings=[],
            )

    class FakePreparer:
        def prepare_usermode_plan(self, _manifest, workspace):
            return SimpleNamespace(
                qemu_binary=Path("qemu-mipsel-static"),
                launch_root=workspace.emulation_dir / "rootfs",
                launcher_script=workspace.emulation_dir / "launch.sh",
                env={},
                warnings=[],
            )

    class FakeSettings:
        def get(self, key: str, default=None):
            if key == "runtime.run_root":
                return str(tmp_path / "external-runtime")
            return default

    class FakeSettingsManager:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def load(self):
            return FakeSettings()

    monkeypatch.setattr(vuln_tools, "FirmwareExtractor", FakeExtractor, raising=False)
    monkeypatch.setattr(vuln_tools, "EmulationPreparer", FakePreparer, raising=False)
    monkeypatch.setattr(vuln_tools, "SettingsManager", FakeSettingsManager, raising=False)

    registry = ToolRegistry()
    register_all_vuln_tools(registry)
    tool = registry.get("firmware_emulation_prepare")
    assert tool is not None

    with bind_runtime_run_id("demo-run-42"):
        result = tool.executor({"path": str(artifact)})

    assert result.return_code == 0
    assert "WORKSPACE_ROOT:" in result.stdout
    assert "demo-run-42" in result.stdout


def test_file_read_tool_reads_local_file() -> None:
    registry = ToolRegistry()
    register_all_vuln_tools(registry)
    tool = registry.get("file_read")
    assert tool is not None

    result = tool.executor({"path": str(Path(__file__))})
    assert result.return_code == 0
    assert "test_file_read_tool_reads_local_file" in result.stdout


def test_python_exec_tool_returns_command_output() -> None:
    registry = ToolRegistry()
    register_all_vuln_tools(registry)
    tool = registry.get("python_exec")
    assert tool is not None

    result = tool.executor({"code": "print('firmware-triage-ok')"})
    assert result.return_code == 0
    assert "firmware-triage-ok" in result.stdout


def test_openai_client_invoke_accepts_string_response_payload() -> None:
    from vulnagent.llm.openai_client import OpenAIClient

    class FakeCompletions:
        def create(self, **_kwargs):
            return "Artifact-first fallback summary"

    class FakeChat:
        def __init__(self) -> None:
            self.completions = FakeCompletions()

    class FakeOpenAI:
        def __init__(self, *args, **kwargs) -> None:
            self.chat = FakeChat()

    class FakeAsyncOpenAI:
        def __init__(self, *args, **kwargs) -> None:
            self.chat = FakeChat()

    with patch("vulnagent.llm.openai_client.OpenAI", FakeOpenAI), patch(
        "vulnagent.llm.openai_client.AsyncOpenAI", FakeAsyncOpenAI
    ):
        client = OpenAIClient(api_key="demo", base_url="http://127.0.0.1:9999/v1", default_model="gpt-5.4")
        response = client.invoke(messages=[{"role": "user", "content": "Summarize this firmware."}])

    assert response.content == "Artifact-first fallback summary"
    assert response.tool_calls == []
    assert response.finish_reason == "stop"


def test_openai_client_invoke_strips_raw_sse_string_payload_without_content() -> None:
    from vulnagent.llm.openai_client import OpenAIClient

    sse_payload = "".join([
        'data: {"id":"","object":"chat.completion.chunk","created":0,',
        '"model":"gpt-5.4","system_fingerprint":"","choices":[],',
        '"usage":{"prompt_tokens":2929,"completion_tokens":0,"total_tokens":2929}}',
        chr(10),
        'data: [DONE]',
        chr(10),
    ])

    class FakeCompletions:
        def create(self, **_kwargs):
            return sse_payload

    class FakeChat:
        def __init__(self) -> None:
            self.completions = FakeCompletions()

    class FakeOpenAI:
        def __init__(self, *args, **kwargs) -> None:
            self.chat = FakeChat()

    class FakeAsyncOpenAI:
        def __init__(self, *args, **kwargs) -> None:
            self.chat = FakeChat()

    with patch("vulnagent.llm.openai_client.OpenAI", FakeOpenAI), patch(
        "vulnagent.llm.openai_client.AsyncOpenAI", FakeAsyncOpenAI
    ):
        client = OpenAIClient(api_key="demo", base_url="http://127.0.0.1:9999/v1", default_model="gpt-5.4")
        response = client.invoke(messages=[{"role": "user", "content": "Summarize this firmware."}])

    assert response.content == ""
    assert response.tool_calls == []
    assert response.finish_reason == "stop"


def _sample_elf64() -> bytes:
    ident = b"\x7fELF" + bytes([2, 1, 1, 0, 0]) + bytes(7)
    header = struct.pack(
        "<HHIQQQIHHHHHH",
        2,
        62,
        1,
        0x401000,
        64,
        0,
        0,
        64,
        56,
        1,
        64,
        0,
        0,
    )
    return ident + header


def test_file_identify_tool_uses_python_fallback(monkeypatch, tmp_path: Path) -> None:
    import vulnagent.tools.vuln_tools as vuln_tools

    sample = tmp_path / "sample.elf"
    sample.write_bytes(_sample_elf64())
    monkeypatch.setattr(vuln_tools, "_command_available", lambda name: False, raising=False)

    registry = ToolRegistry()
    register_all_vuln_tools(registry)
    tool = registry.get("file_identify")
    assert tool is not None

    result = tool.executor({"path": str(sample)})
    assert result.return_code == 0
    assert "ELF" in result.stdout
    assert "x86-64" in result.stdout


def test_readelf_headers_tool_uses_python_fallback(monkeypatch, tmp_path: Path) -> None:
    import vulnagent.tools.vuln_tools as vuln_tools

    sample = tmp_path / "sample.elf"
    sample.write_bytes(_sample_elf64())
    monkeypatch.setattr(vuln_tools, "_command_available", lambda name: False, raising=False)

    registry = ToolRegistry()
    register_all_vuln_tools(registry)
    tool = registry.get("readelf_headers")
    assert tool is not None

    result = tool.executor({"path": str(sample)})
    assert result.return_code == 0
    assert "ELF Header" in result.stdout
    assert "x86-64" in result.stdout


def test_strings_extract_tool_uses_python_fallback(monkeypatch, tmp_path: Path) -> None:
    import vulnagent.tools.vuln_tools as vuln_tools

    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"\x00admin\x00password123\x00http://router.local\x00")
    monkeypatch.setattr(vuln_tools, "_command_available", lambda name: False, raising=False)

    registry = ToolRegistry()
    register_all_vuln_tools(registry)
    tool = registry.get("strings_extract")
    assert tool is not None

    result = tool.executor({"path": str(sample)})
    assert result.return_code == 0
    assert "admin" in result.stdout
    assert "password123" in result.stdout


def test_binwalk_scan_tool_uses_python_fallback(monkeypatch, tmp_path: Path) -> None:
    import vulnagent.tools.vuln_tools as vuln_tools

    sample = tmp_path / "firmware.bin"
    sample.write_bytes(b"A" * 16 + b"hsqs" + b"B" * 20 + b"\x1f\x8b\x08" + b"C" * 10)
    monkeypatch.setattr(vuln_tools, "_command_available", lambda name: False, raising=False)

    registry = ToolRegistry()
    register_all_vuln_tools(registry)
    tool = registry.get("binwalk_scan")
    assert tool is not None

    result = tool.executor({"path": str(sample)})
    assert result.return_code == 0
    assert "SquashFS" in result.stdout
    assert "gzip" in result.stdout


def test_firmware_emulation_probe_uses_service_type_dispatch(monkeypatch) -> None:
    import vulnagent.tools.vuln_tools as vuln_tools

    class FakeRunner:
        def __init__(self, remote_executor=None):
            pass
        def probe_service(self, service_type: str, port: int, host: str = "127.0.0.1"):
            assert service_type == "telnet"
            assert port == 2323
            assert host == "127.0.0.1"
            return SimpleNamespace(
                service_type="telnet",
                endpoint="telnet://127.0.0.1:2323",
                reachable=True,
                summary="banner-ok",
                details="BusyBox telnetd",
            )

    monkeypatch.setattr(vuln_tools, "EmulationRunner", FakeRunner, raising=False)

    registry = ToolRegistry()
    register_all_vuln_tools(registry)
    tool = registry.get("firmware_emulation_probe")
    assert tool is not None

    result = tool.executor({"port": 2323, "service_type": "telnet"})

    assert result.return_code == 0
    assert "SERVICE_TYPE: telnet" in result.stdout
    assert "ENDPOINT: telnet://127.0.0.1:2323" in result.stdout
    assert "SUMMARY: banner-ok" in result.stdout


def test_firmware_emulation_launch_user_emits_probe_hints(monkeypatch, tmp_path: Path) -> None:
    import vulnagent.tools.vuln_tools as vuln_tools
    from vulnagent.firmware.workspace import RuntimeWorkspaceManager

    artifact = tmp_path / "firmware.img"
    artifact.write_bytes(b"demo")
    rootfs = tmp_path / "rootfs"
    (rootfs / "bin").mkdir(parents=True)
    busybox_path = rootfs / "bin" / "busybox"
    busybox_path.write_bytes(b"\x7fELF" + b"\x01" * 128)

    class FakeExtractor:
        def build_manifest(self, _artifact, _workspace):
            return SimpleNamespace(
                rootfs_path=rootfs,
                architecture="mips",
                endianness="little",
                warnings=[],
            )

    class FakePreparer:
        def prepare_usermode_plan(self, _manifest, workspace):
            launch_root = workspace.emulation_dir / "rootfs"
            launch_root.mkdir(parents=True, exist_ok=True)
            return SimpleNamespace(
                qemu_binary=Path("qemu-mipsel-static"),
                launch_root=launch_root,
                launcher_script=workspace.emulation_dir / "launch.sh",
                env={},
                warnings=[],
            )

    class FakeRunner:
        def __init__(self, remote_executor=None):
            pass
        def build_command(self, plan, candidate, _source_root):
            return [
                str(plan.qemu_binary),
                "-L",
                str(plan.launch_root),
                str(candidate.binary_path),
                *candidate.launch_argv[1:],
            ]

        def run_candidate(self, _plan, command, *, cwd=None, timeout=15):
            return SimpleNamespace(
                command=command,
                return_code=0,
                stdout="",
                stderr="",
                log_path=Path(cwd or tmp_path) / "launch.log",
            )

    candidate = SimpleNamespace(
        service_type="http",
        binary_name="busybox",
        binary_path=busybox_path.resolve(),
        launch_argv=["busybox", "httpd", "-f", "-p", "8080"],
        confidence=0.95,
        source="filesystem",
        probe_port=8080,
        probe_scheme="http",
    )

    monkeypatch.setattr(vuln_tools, "FirmwareExtractor", FakeExtractor, raising=False)
    monkeypatch.setattr(vuln_tools, "EmulationPreparer", FakePreparer, raising=False)
    monkeypatch.setattr(vuln_tools, "EmulationRunner", FakeRunner, raising=False)
    monkeypatch.setattr(
        vuln_tools,
        "build_service_inventory",
        lambda _rootfs: SimpleNamespace(rootfs=rootfs, service_candidates=[candidate]),
        raising=False,
    )
    monkeypatch.setattr(
        vuln_tools,
        "_runtime_workspace_manager",
        lambda: RuntimeWorkspaceManager(base_root=tmp_path / "runs"),
        raising=False,
    )

    registry = ToolRegistry()
    register_all_vuln_tools(registry)
    tool = registry.get("firmware_emulation_launch_user")
    assert tool is not None

    result = tool.executor({"path": str(artifact)})

    assert result.return_code == 0
    assert "PROBE_PORT: 8080" in result.stdout
    assert "PROBE_SCHEME: http" in result.stdout
    assert "PROBE_ENDPOINT: http://127.0.0.1:8080/" in result.stdout


def test_firmware_extract_summary_tool_uses_python_squashfs(monkeypatch, tmp_path: Path) -> None:
    import vulnagent.tools.vuln_tools as vuln_tools

    class FakeFileHandle:
        def __init__(self, data: bytes) -> None:
            self._data = data

        def read(self, *_args, **_kwargs) -> bytes:
            return self._data

    class FakeNode:
        def __init__(
            self,
            name: str,
            *,
            is_dir: bool = False,
            data: bytes = b"",
            children: list["FakeNode"] | None = None,
        ) -> None:
            self.name = name
            self._is_dir = is_dir
            self._data = data
            self._children = list(children or [])

        def is_dir(self) -> bool:
            return self._is_dir

        def is_file(self) -> bool:
            return not self._is_dir

        def iterdir(self):
            return iter(self._children)

        def listdir(self):
            return [child.name for child in self._children]

        def open(self):
            return FakeFileHandle(self._data)

    class FakeSquashFS:
        def __init__(self, _fileobj) -> None:
            root_children = [
                FakeNode("bin", is_dir=True),
                FakeNode("etc_ro", is_dir=True),
            ]
            self._nodes = {
                "/": FakeNode("/", is_dir=True, children=root_children),
                "/etc_ro/rcS": FakeNode("rcS", data=b"#!/bin/sh\ntelnetd\ngoahead&\n"),
                "/etc_ro/inittab": FakeNode("inittab", data=b"::sysinit:/etc_ro/rcS\nttyS1::respawn:/bin/sh\n"),
                "/bin/goahead": FakeNode(
                    "goahead",
                    data=b"showSystemCommandASP\x00upload.cgi\x00form2Telnet.cgi\x00",
                ),
                "/etc_ro/web/cgi-bin/upload.cgi": FakeNode("upload.cgi", data=b"#!/bin/sh\n"),
                "/etc_ro/web/d_telnet.asp": FakeNode("d_telnet.asp", data=b"<form></form>\n"),
            }

        def get(self, path: str):
            normalized = path if path.startswith("/") else f"/{path}"
            return self._nodes[normalized]

    sample = tmp_path / "firmware.bin"
    sample.write_bytes(b"A" * 16 + b"hsqs" + b"B" * 32)
    monkeypatch.setattr(vuln_tools, "_command_available", lambda name: False, raising=False)
    monkeypatch.setattr(vuln_tools, "_find_squashfs_offsets", lambda blob, max_candidates=8: [16], raising=False)
    monkeypatch.setattr(vuln_tools, "_load_squashfs_class", lambda: FakeSquashFS, raising=False)

    registry = ToolRegistry()
    register_all_vuln_tools(registry)
    tool = registry.get("firmware_extract_summary")
    assert tool is not None

    result = tool.executor({"path": str(sample)})
    assert result.return_code == 0
    assert "SQUASHFS_FOUND offset=0x00000010" in result.stdout
    assert "INTERESTING_PATH: /etc_ro/rcS" in result.stdout
    assert "TEXT_HIT: /etc_ro/rcS :: telnetd" in result.stdout
    assert "TEXT_HIT: /etc_ro/inittab :: ttyS1::respawn:/bin/sh" in result.stdout
    assert "BINARY_STRING: /bin/goahead :: showSystemCommandASP" in result.stdout


def test_firmware_read_path_reads_text_and_binary_strings(monkeypatch, tmp_path: Path) -> None:
    import vulnagent.tools.vuln_tools as vuln_tools

    class FakeFileHandle:
        def __init__(self, data: bytes) -> None:
            self._data = data

        def read(self, *_args, **_kwargs) -> bytes:
            return self._data

    class FakeNode:
        def __init__(self, data: bytes) -> None:
            self._data = data

        def is_file(self) -> bool:
            return True

        def open(self):
            return FakeFileHandle(self._data)

    class FakeSquashFS:
        def __init__(self, _fileobj) -> None:
            self._nodes = {
                "/etc_ro/web/dir_login.asp": FakeNode(b"<form action=\"goform/formLogin\"></form>\n"),
                "/bin/goahead": FakeNode(b"showSystemCommandASP\x00upload.cgi\x00form2Telnet.cgi\x00"),
            }

        def get(self, path: str):
            normalized = path if path.startswith("/") else f"/{path}"
            return self._nodes[normalized]

    sample = tmp_path / "firmware.bin"
    sample.write_bytes(b"A" * 16 + b"hsqs" + b"B" * 32)
    monkeypatch.setattr(vuln_tools, "_find_squashfs_offsets", lambda blob, max_candidates=8: [16], raising=False)
    monkeypatch.setattr(vuln_tools, "_load_squashfs_class", lambda: FakeSquashFS, raising=False)

    registry = ToolRegistry()
    register_all_vuln_tools(registry)
    tool = registry.get("firmware_read_path")
    assert tool is not None

    text_result = tool.executor({
        "path": str(sample),
        "inner_path": "/etc_ro/web/dir_login.asp",
        "mode": "text",
    })
    assert text_result.return_code == 0
    assert "goform/formLogin" in text_result.stdout

    strings_result = tool.executor({
        "path": str(sample),
        "inner_path": "/bin/goahead",
        "mode": "strings",
    })
    assert strings_result.return_code == 0
    assert "showSystemCommandASP" in strings_result.stdout
    assert "upload.cgi" in strings_result.stdout


def test_firmware_read_path_auto_mode_switches_binary_to_strings(monkeypatch, tmp_path: Path) -> None:
    import vulnagent.tools.vuln_tools as vuln_tools

    class FakeFileHandle:
        def __init__(self, data: bytes) -> None:
            self._data = data

        def read(self, *_args, **_kwargs) -> bytes:
            return self._data

    class FakeNode:
        def __init__(self, data: bytes) -> None:
            self._data = data

        def is_file(self) -> bool:
            return True

        def open(self):
            return FakeFileHandle(self._data)

    class FakeSquashFS:
        def __init__(self, _fileobj) -> None:
            self._nodes = {
                "/etc_ro/web/cgi-bin/upload.cgi": FakeNode(
                    b"\x7fELF" + b"\x00" * 64 + b"system\x00/var/webupload\x00upload.cgi.c\x00",
                ),
            }

        def get(self, path: str):
            normalized = path if path.startswith("/") else f"/{path}"
            return self._nodes[normalized]

    sample = tmp_path / "firmware.bin"
    sample.write_bytes(b"A" * 16 + b"hsqs" + b"B" * 32)
    monkeypatch.setattr(vuln_tools, "_find_squashfs_offsets", lambda blob, max_candidates=8: [16], raising=False)
    monkeypatch.setattr(vuln_tools, "_load_squashfs_class", lambda: FakeSquashFS, raising=False)

    registry = ToolRegistry()
    register_all_vuln_tools(registry)
    tool = registry.get("firmware_read_path")
    assert tool is not None

    result = tool.executor({
        "path": str(sample),
        "inner_path": "/etc_ro/web/cgi-bin/upload.cgi",
        "mode": "auto",
    })
    assert result.return_code == 0
    assert "[auto-mode:strings]" in result.stdout
    assert "system" in result.stdout
    assert "/var/webupload" in result.stdout


def test_firmware_search_finds_text_and_binary_references(monkeypatch, tmp_path: Path) -> None:
    import vulnagent.tools.vuln_tools as vuln_tools

    class FakeFileHandle:
        def __init__(self, data: bytes) -> None:
            self._data = data

        def read(self, *_args, **_kwargs) -> bytes:
            return self._data

    class FakeNode:
        def __init__(
            self,
            name: str,
            *,
            is_dir: bool = False,
            data: bytes = b"",
            children: list["FakeNode"] | None = None,
        ) -> None:
            self.name = name
            self._is_dir = is_dir
            self._data = data
            self._children = list(children or [])

        def is_dir(self) -> bool:
            return self._is_dir

        def is_file(self) -> bool:
            return not self._is_dir

        def iterdir(self):
            return iter(self._children)

        def open(self):
            return FakeFileHandle(self._data)

    class FakeSquashFS:
        def __init__(self, _fileobj) -> None:
            telnet_node = FakeNode(
                "d_telnet.asp",
                data=b"<form action=\"/goform/form2Telnet.cgi\"></form>\n",
            )
            login_node = FakeNode(
                "dir_login.asp",
                data=b"<form action=\"goform/formLogin\"></form>\n",
            )
            web_dir = FakeNode("web", is_dir=True, children=[telnet_node, login_node])
            etc_ro_dir = FakeNode("etc_ro", is_dir=True, children=[web_dir])
            goahead_node = FakeNode(
                "goahead",
                data=b"showSystemCommandASP\x00form2Telnet.cgi\x00goform/formLogin\x00",
            )
            bin_dir = FakeNode("bin", is_dir=True, children=[goahead_node])
            self._nodes = {
                "/": FakeNode("/", is_dir=True, children=[etc_ro_dir, bin_dir]),
                "/etc_ro": etc_ro_dir,
                "/etc_ro/web": web_dir,
                "/etc_ro/web/d_telnet.asp": telnet_node,
                "/etc_ro/web/dir_login.asp": login_node,
                "/bin": bin_dir,
                "/bin/goahead": goahead_node,
            }

        def get(self, path: str):
            normalized = path if path.startswith("/") else f"/{path}"
            return self._nodes[normalized]

    sample = tmp_path / "firmware.bin"
    sample.write_bytes(b"A" * 16 + b"hsqs" + b"B" * 32)
    monkeypatch.setattr(vuln_tools, "_find_squashfs_offsets", lambda blob, max_candidates=8: [16], raising=False)
    monkeypatch.setattr(vuln_tools, "_load_squashfs_class", lambda: FakeSquashFS, raising=False)

    registry = ToolRegistry()
    register_all_vuln_tools(registry)
    tool = registry.get("firmware_search")
    assert tool is not None

    result = tool.executor({
        "path": str(sample),
        "pattern": "form2Telnet.cgi",
        "max_results": 10,
    })
    assert result.return_code == 0
    assert "SEARCH_PATTERN: form2Telnet.cgi" in result.stdout
    assert "MATCH: /etc_ro/web/d_telnet.asp [text]" in result.stdout
    assert "MATCH: /bin/goahead [strings] :: form2Telnet.cgi" in result.stdout


def test_firmware_web_surface_map_extracts_routes_and_correlations(monkeypatch, tmp_path: Path) -> None:
    import vulnagent.tools.vuln_tools as vuln_tools

    class FakeFileHandle:
        def __init__(self, data: bytes) -> None:
            self._data = data

        def read(self, *_args, **_kwargs) -> bytes:
            return self._data

    class FakeNode:
        def __init__(
            self,
            name: str,
            *,
            is_dir: bool = False,
            data: bytes = b"",
            children: list["FakeNode"] | None = None,
        ) -> None:
            self.name = name
            self._is_dir = is_dir
            self._data = data
            self._children = list(children or [])

        def is_dir(self) -> bool:
            return self._is_dir

        def is_file(self) -> bool:
            return not self._is_dir

        def iterdir(self):
            return iter(self._children)

        def open(self):
            return FakeFileHandle(self._data)

    class FakeSquashFS:
        def __init__(self, _fileobj) -> None:
            telnet_page = FakeNode(
                "d_telnet.asp",
                data=b"<form action=\"/goform/form2Telnet.cgi\"></form>\n",
            )
            login_page = FakeNode(
                "dir_login.asp",
                data=b"<form action=\"goform/formLogin\"></form>\n",
            )
            saveconf_page = FakeNode(
                "d_saveconf.asp",
                data=(
                    b"<form action=\"/cgi-bin/upload_settings.cgi\"></form>\n"
                    b"<a href=\"/cgi-bin/ExportSettings.sh\">export</a>\n"
                ),
            )
            upload_page = FakeNode(
                "d_upload.asp",
                data=b"<form action=\"/cgi-bin/upload.cgi\"></form>\n",
            )
            wps_page = FakeNode(
                "d_wl5wps_step1.asp",
                data=b"<form action=\"/goform/fform2Wl5Wsc.cgi\"></form>\n",
            )
            web_dir = FakeNode(
                "web",
                is_dir=True,
                children=[telnet_page, login_page, saveconf_page, upload_page, wps_page],
            )
            etc_ro_dir = FakeNode("etc_ro", is_dir=True, children=[web_dir])
            goahead_node = FakeNode(
                "goahead",
                data=(
                    b"form2Telnet.cgi\x00goform/formLogin\x00"
                    b"/cgi-bin/upload.cgi\x00showSystemCommandASP\x00doSystem\x00"
                ),
            )
            bin_dir = FakeNode("bin", is_dir=True, children=[goahead_node])
            self._nodes = {
                "/": FakeNode("/", is_dir=True, children=[etc_ro_dir, bin_dir]),
                "/etc_ro": etc_ro_dir,
                "/etc_ro/web": web_dir,
                "/etc_ro/web/d_telnet.asp": telnet_page,
                "/etc_ro/web/dir_login.asp": login_page,
                "/etc_ro/web/d_saveconf.asp": saveconf_page,
                "/etc_ro/web/d_upload.asp": upload_page,
                "/etc_ro/web/d_wl5wps_step1.asp": wps_page,
                "/bin": bin_dir,
                "/bin/goahead": goahead_node,
            }

        def get(self, path: str):
            normalized = path if path.startswith("/") else f"/{path}"
            return self._nodes[normalized]

    sample = tmp_path / "firmware.bin"
    sample.write_bytes(b"A" * 16 + b"hsqs" + b"B" * 32)
    monkeypatch.setattr(vuln_tools, "_find_squashfs_offsets", lambda blob, max_candidates=8: [16], raising=False)
    monkeypatch.setattr(vuln_tools, "_load_squashfs_class", lambda: FakeSquashFS, raising=False)

    registry = ToolRegistry()
    register_all_vuln_tools(registry)
    tool = registry.get("firmware_web_surface_map")
    assert tool is not None

    result = tool.executor({"path": str(sample)})
    assert result.return_code == 0
    assert "TEXT_ROUTE: /etc_ro/web/d_telnet.asp -> /goform/form2Telnet.cgi" in result.stdout
    assert "TEXT_ROUTE: /etc_ro/web/dir_login.asp -> goform/formLogin" in result.stdout
    assert "TEXT_ROUTE: /etc_ro/web/d_saveconf.asp -> /cgi-bin/upload_settings.cgi" in result.stdout
    assert "BINARY_ROUTE: /bin/goahead -> /cgi-bin/upload.cgi" in result.stdout
    assert "BINARY_MARKER: /bin/goahead -> showSystemCommandASP" in result.stdout
    assert "ROUTE_CORRELATION: /cgi-bin/upload.cgi" in result.stdout
    assert "d_wl5wps_step1.asp" not in result.stdout
