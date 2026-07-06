from __future__ import annotations

import struct
from pathlib import Path

from vulnagent.firmware.emulation import EmulationPlan, EmulationPreparer, EmulationRunner
from vulnagent.firmware.extract import FirmwareExtractor
from vulnagent.firmware.models import ServiceCandidate
from vulnagent.firmware.inventory import build_service_inventory
from vulnagent.firmware.workspace import RuntimeWorkspaceManager
from vulnagent.utils.dependency_check import check_all_dependencies


def test_workspace_manager_creates_expected_run_tree(tmp_path: Path) -> None:
    artifact = tmp_path / "firmware.bin"
    artifact.write_bytes(b"demo")

    manager = RuntimeWorkspaceManager(base_root=tmp_path / "runs")
    workspace = manager.create_for_artifact(artifact)

    assert workspace.input_dir.is_dir()
    assert workspace.extract_dir.is_dir()
    assert workspace.emulation_dir.is_dir()
    assert workspace.logs_dir.is_dir()
    assert workspace.reports_dir.is_dir()
    assert workspace.artifact_path == artifact.resolve()


def _sample_mips_elf32_lsb() -> bytes:
    ident = b"\x7fELF" + bytes([1, 1, 1, 0, 0]) + bytes(7)
    header = struct.pack(
        "<HHIIIIIHHHHHH",
        2,
        8,
        1,
        0x00400000,
        52,
        0,
        0,
        52,
        32,
        1,
        40,
        0,
        0,
    )
    return ident + header


def test_manifest_detects_rootfs_and_architecture_from_extracted_tree(tmp_path: Path) -> None:
    artifact = tmp_path / "firmware.bin"
    artifact.write_bytes(b"demo")
    workspace = RuntimeWorkspaceManager(base_root=tmp_path / "runs").create_for_artifact(artifact)
    rootfs = workspace.extract_dir / "rootfs"
    (rootfs / "bin").mkdir(parents=True)
    (rootfs / "bin" / "busybox").write_bytes(_sample_mips_elf32_lsb())
    (rootfs / "etc_ro" / "web").mkdir(parents=True)
    (rootfs / "etc_ro" / "rcS").write_text("#!/bin/sh\ntelnetd\ngoahead\n", encoding="utf-8")

    manifest = FirmwareExtractor().build_manifest(artifact, workspace, rootfs_path=rootfs)

    assert manifest.rootfs_path == rootfs
    assert manifest.architecture == "mips"
    assert manifest.endianness == "little"
    assert "/etc_ro/rcS" in manifest.init_candidates
    assert "/etc_ro/web" in manifest.web_roots


def test_service_inventory_ranks_http_before_telnet(tmp_path: Path) -> None:
    rootfs = tmp_path / "rootfs"
    (rootfs / "bin").mkdir(parents=True)
    (rootfs / "usr" / "sbin").mkdir(parents=True)
    (rootfs / "bin" / "busybox").write_bytes(_sample_mips_elf32_lsb())
    (rootfs / "usr" / "sbin" / "telnetd").write_text("placeholder", encoding="utf-8")

    inventory = build_service_inventory(rootfs)

    assert inventory.service_candidates
    http_candidate = inventory.service_candidates[0]
    assert http_candidate.service_type == "http"
    assert http_candidate.probe_port == 8080
    assert http_candidate.probe_scheme == "http"

    telnet_candidate = next(item for item in inventory.service_candidates if item.binary_name == "telnetd")
    assert telnet_candidate.service_type == "telnet"
    assert telnet_candidate.probe_port == 2323
    assert telnet_candidate.probe_scheme == "telnet"


def test_service_inventory_derives_busybox_telnet_candidate_from_init_script(tmp_path: Path) -> None:
    rootfs = tmp_path / "rootfs"
    (rootfs / "bin").mkdir(parents=True)
    (rootfs / "etc_ro").mkdir(parents=True)
    (rootfs / "bin" / "busybox").write_bytes(_sample_mips_elf32_lsb())
    (rootfs / "etc_ro" / "rcS").write_text("#!/bin/sh\ntelnetd -l /bin/login\n", encoding="utf-8")

    inventory = build_service_inventory(rootfs)

    telnet_candidate = next(
        item
        for item in inventory.service_candidates
        if item.binary_name == "busybox" and item.service_type == "telnet"
    )
    assert telnet_candidate.launch_argv[:2] == ["busybox", "telnetd"]
    assert telnet_candidate.probe_port == 2323
    assert telnet_candidate.probe_scheme == "telnet"


def test_emulation_preparer_selects_mipsel_qemu_binary() -> None:
    preparer = EmulationPreparer(
        command_lookup=lambda name: f"/usr/bin/{name}" if name == "qemu-mipsel-static" else None
    )

    selected = preparer.select_qemu_binary("mips", "little")

    assert selected.name == "qemu-mipsel-static"


def test_emulation_preparer_accepts_windows_qemu_binary_name() -> None:
    preparer = EmulationPreparer(
        command_lookup=lambda name: f"C:/QEMU/{name}" if name == "qemu-mipsel.exe" else None
    )

    selected = preparer.select_qemu_binary("mips", "little")

    assert selected.name == "qemu-mipsel.exe"


def test_emulation_preparer_copies_rootfs_and_writes_launcher(tmp_path: Path) -> None:
    artifact = tmp_path / "firmware.bin"
    artifact.write_bytes(b"demo")
    workspace = RuntimeWorkspaceManager(base_root=tmp_path / "runs").create_for_artifact(artifact)
    rootfs = workspace.extract_dir / "rootfs"
    (rootfs / "bin").mkdir(parents=True)
    (rootfs / "bin" / "busybox").write_bytes(_sample_mips_elf32_lsb())

    manifest = FirmwareExtractor().build_manifest(artifact, workspace, rootfs_path=rootfs)
    preparer = EmulationPreparer(
        command_lookup=lambda name: f"/usr/bin/{name}" if name == "qemu-mipsel-static" else None
    )

    plan = preparer.prepare_usermode_plan(manifest, workspace)

    assert plan.launch_root.is_dir()
    assert (plan.launch_root / "bin" / "busybox").is_file()
    assert plan.launcher_script.is_file()


def test_emulation_runner_builds_qemu_wrapped_command(tmp_path: Path) -> None:
    launch_root = tmp_path / "emulation-rootfs"
    (launch_root / "bin").mkdir(parents=True)
    (launch_root / "bin" / "busybox").write_bytes(_sample_mips_elf32_lsb())
    source_root = tmp_path / "extract-rootfs"
    (source_root / "bin").mkdir(parents=True)
    (source_root / "bin" / "busybox").write_bytes(_sample_mips_elf32_lsb())

    plan = EmulationPlan(
        qemu_binary=Path("C:/QEMU/qemu-mipsel.exe"),
        launch_root=launch_root,
        launcher_script=tmp_path / "launch.sh",
        env={},
        warnings=[],
    )
    candidate = ServiceCandidate(
        service_type="http",
        binary_name="busybox",
        binary_path=(source_root / "bin" / "busybox").resolve(),
        launch_argv=["busybox", "httpd", "-f", "-p", "8080"],
        confidence=0.9,
        source="filesystem",
    )

    command = EmulationRunner().build_command(plan, candidate, source_root)

    assert command[0].endswith("qemu-mipsel.exe")
    assert "-L" in command
    assert str(launch_root) in command
    assert any(part.endswith("busybox") for part in command)
    assert "httpd" in command


def test_dependency_report_exposes_emulation_category() -> None:
    results = check_all_dependencies()

    assert "emulation" in results
