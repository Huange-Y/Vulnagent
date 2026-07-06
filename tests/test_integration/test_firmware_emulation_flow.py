from __future__ import annotations

import lzma
import struct
from pathlib import Path

from vulnagent.firmware.emulation import EmulationPlan, EmulationRunner, build_systemmode_package, build_systemmode_plan
from vulnagent.firmware.extract import FirmwareExtractor
from vulnagent.firmware.workspace import RuntimeWorkspaceManager


def test_emulation_runner_records_launch_failure(tmp_path: Path) -> None:
    runner = EmulationRunner()
    plan = EmulationPlan(
        qemu_binary=Path("qemu-mipsel-static"),
        launch_root=tmp_path,
        launcher_script=tmp_path / "launch.sh",
        env={},
        warnings=[],
    )

    result = runner.run_candidate(plan, ["definitely-not-a-real-binary"], cwd=tmp_path)

    assert result.command
    assert result.return_code != 0
    assert result.stderr


def test_build_systemmode_package_writes_boot_prerequisites(tmp_path: Path) -> None:
    artifact = tmp_path / "firmware.bin"
    artifact.write_bytes(b"demo")
    workspace = RuntimeWorkspaceManager(base_root=tmp_path / "runs").create_for_artifact(artifact)
    rootfs = workspace.extract_dir / "rootfs"
    (rootfs / "bin").mkdir(parents=True)
    (rootfs / "bin" / "busybox").write_bytes(b"\x7fELF" + b"\x01" * 128)

    manifest = FirmwareExtractor().build_manifest(artifact, workspace, rootfs_path=rootfs)
    package_path = build_systemmode_package(manifest, workspace)

    assert package_path.is_file()
    text = package_path.read_text(encoding="utf-8")
    assert "arch=" in text
    assert "rootfs=" in text


def _sample_uimage(payload: bytes, *, compression: int = 0, arch: int = 5, name: bytes = b"Linux Kernel Image") -> bytes:
    header = struct.pack(
        ">7I4B32s",
        0x27051956,
        0,
        0,
        len(payload),
        0x80000000,
        0x80001000,
        0,
        5,
        arch,
        2,
        compression,
        name.ljust(32, b"\0"),
    )
    return header + payload


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


def test_build_systemmode_plan_extracts_uimage_payload_and_selects_windows_qemu(tmp_path: Path) -> None:
    artifact = tmp_path / "firmware.img"
    payload = b"\x7fELF" + b"\x01" * 124
    artifact.write_bytes(_sample_uimage(payload))
    workspace = RuntimeWorkspaceManager(base_root=tmp_path / "runs").create_for_artifact(artifact)
    rootfs = workspace.extract_dir / "rootfs"
    (rootfs / "bin").mkdir(parents=True)
    (rootfs / "bin" / "busybox").write_bytes(_sample_mips_elf32_lsb())
    manifest = FirmwareExtractor().build_manifest(artifact, workspace, rootfs_path=rootfs)

    plan = build_systemmode_plan(
        manifest,
        workspace,
        command_lookup=lambda name: f"C:/Program Files/qemu/{name}" if name == "qemu-system-mipsel.exe" else None,
    )

    assert plan.qemu_binary is not None
    assert plan.qemu_binary.name == "qemu-system-mipsel.exe"
    assert plan.machine == "malta"
    assert plan.kernel_candidates
    assert any(candidate.name == "kernel.payload.bin" for candidate in plan.kernel_candidates)
    assert plan.package_dir.is_dir()


def test_build_systemmode_plan_finds_qemu_in_program_files_fallback(monkeypatch, tmp_path: Path) -> None:
    program_files = tmp_path / "Program Files"
    qemu_dir = program_files / "qemu"
    qemu_dir.mkdir(parents=True)
    (qemu_dir / "qemu-system-mipsel.exe").write_text("", encoding="utf-8")

    artifact = tmp_path / "firmware.img"
    artifact.write_bytes(_sample_uimage(b"kernel"))
    workspace = RuntimeWorkspaceManager(base_root=tmp_path / "runs").create_for_artifact(artifact)
    rootfs = workspace.extract_dir / "rootfs"
    (rootfs / "bin").mkdir(parents=True)
    (rootfs / "bin" / "busybox").write_bytes(_sample_mips_elf32_lsb())
    manifest = FirmwareExtractor().build_manifest(artifact, workspace, rootfs_path=rootfs)

    monkeypatch.setenv("ProgramFiles", str(program_files))
    monkeypatch.delenv("ProgramFiles(x86)", raising=False)
    plan = build_systemmode_plan(manifest, workspace, command_lookup=lambda _name: None)

    assert plan.qemu_binary is not None
    assert plan.qemu_binary.name == "qemu-system-mipsel.exe"


def test_build_systemmode_plan_wraps_lzma_raw_kernel_into_synthetic_elf(tmp_path: Path) -> None:
    artifact = tmp_path / "firmware.img"
    raw_kernel = b"\0" * 0x200 + b"MIPSKERNEL" + b"\0" * 0x400
    artifact.write_bytes(_sample_uimage(lzma.compress(raw_kernel), compression=3))
    workspace = RuntimeWorkspaceManager(base_root=tmp_path / "runs").create_for_artifact(artifact)
    rootfs = workspace.extract_dir / "rootfs"
    (rootfs / "bin").mkdir(parents=True)
    (rootfs / "bin" / "busybox").write_bytes(_sample_mips_elf32_lsb())
    manifest = FirmwareExtractor().build_manifest(artifact, workspace, rootfs_path=rootfs)

    plan = build_systemmode_plan(
        manifest,
        workspace,
        command_lookup=lambda name: f"C:/Program Files/qemu/{name}" if name == "qemu-system-mipsel.exe" else None,
    )

    names = [candidate.name for candidate in plan.kernel_candidates]
    assert "kernel.payload.raw" in names
    assert "kernel.payload.elf" in names

    synthetic = next(candidate for candidate in plan.kernel_candidates if candidate.name == "kernel.payload.elf")
    header = synthetic.read_bytes()[:16]
    assert header.startswith(b"\x7fELF")
    assert header[4] == 1
    assert header[5] == 1
    assert any(
        "loader,file=" in " ".join(command)
        and "kernel.payload.raw" in " ".join(command)
        for command in plan.attempted_commands
    )


def test_build_systemmode_plan_ignores_false_embedded_elf_hits_in_lzma_payload(tmp_path: Path) -> None:
    artifact = tmp_path / "firmware.img"
    false_marker = (
        b"\0" * 0x200
        + b"\x7fELF\x00\x00\x00\x00__param\0__ksymtab\0__kcrctab\0"
        + b"\0" * 0x400
    )
    artifact.write_bytes(_sample_uimage(lzma.compress(false_marker), compression=3))
    workspace = RuntimeWorkspaceManager(base_root=tmp_path / "runs").create_for_artifact(artifact)
    rootfs = workspace.extract_dir / "rootfs"
    (rootfs / "bin").mkdir(parents=True)
    (rootfs / "bin" / "busybox").write_bytes(_sample_mips_elf32_lsb())
    manifest = FirmwareExtractor().build_manifest(artifact, workspace, rootfs_path=rootfs)

    plan = build_systemmode_plan(
        manifest,
        workspace,
        command_lookup=lambda name: f"C:/Program Files/qemu/{name}" if name == "qemu-system-mipsel.exe" else None,
    )

    names = [candidate.name for candidate in plan.kernel_candidates]
    assert "kernel.payload.elf" in names
    assert not any(name.startswith("kernel.elf-candidate-") for name in names)


def test_emulation_runner_records_systemmode_attempt_errors(tmp_path: Path) -> None:
    runner = EmulationRunner()
    log_path = tmp_path / "system.log"

    result = runner.run_command(["definitely-not-a-real-qemu"], log_path=log_path, timeout=5)

    assert result.return_code != 0
    assert log_path.is_file()
    assert result.stderr
