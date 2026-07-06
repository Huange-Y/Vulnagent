from __future__ import annotations

from langchain_core.messages import AIMessage, HumanMessage

from vulnagent.core.assessment import build_report_sections, ensure_run_metadata, make_finding


def test_ensure_run_metadata_records_scope_and_provenance() -> None:
    metadata = ensure_run_metadata(
        target="firmware.bin",
        scope="filesystem triage",
        provenance="artifact:firmware.bin",
    )
    assert metadata["target"] == "firmware.bin"
    assert metadata["scope"] == "filesystem triage"
    assert metadata["provenance"] == "artifact:firmware.bin"
    assert metadata["execution_mode"] == "operator-directed"


def test_make_finding_preserves_artifact_context() -> None:
    finding = make_finding(
        title="BusyBox 1.15 present",
        stage="discovery",
        source="artifact",
        severity="medium",
        evidence=["/bin/busybox"],
        component_path="/bin/busybox",
    )
    assert finding["status"] == "candidate"
    assert finding["source"] == "artifact"
    assert finding["component_path"] == "/bin/busybox"


def test_build_report_sections_handles_no_findings() -> None:
    report = build_report_sections(
        target="lab-vm",
        scope="http admin only",
        provenance="live:10.0.0.5",
        confirmed_findings=[],
        validated_leads=[],
        candidate_findings=[{"title": "auth bypass lead", "status": "candidate"}],
        evidence=["whatweb: boa"],
        priority_targets=[{"title": "login.cgi auth flow", "priority": "high", "validation_focus": "trace auth gate"}],
        next_steps=["manually trace login.cgi"],
    )
    assert "Executive Summary" in report
    assert "Scope" in report
    assert "Validated Leads" in report
    assert "Unconfirmed Leads" in report
    assert "Priority Targets" in report
    assert "Validation Closure" in report
    assert "manually trace login.cgi" not in report


def test_collect_artifact_observations_promotes_successful_emulation_probe_to_confirmed_finding() -> None:
    from vulnagent.core.assessment import collect_artifact_observations

    observations = collect_artifact_observations(
        {
            "firmware_emulation_launch_user": (
                "EXECUTION_BACKEND: local\n"
                "SERVICE_TYPE: http\n"
                "PROBE_SERVICE_TYPE: http\n"
                "PROBE_PORT: 8080\n"
                "PROBE_SCHEME: http\n"
                "PROBE_ENDPOINT: http://127.0.0.1:8080/\n"
            ),
            "firmware_emulation_probe": (
                "SERVICE_TYPE: http\n"
                "ENDPOINT: http://127.0.0.1:8080/\n"
                "REACHABLE: true\n"
                "SUMMARY: 200 OK\n"
                "DETAILS: <html>login</html>\n"
            ),
        }
    )

    confirmed_titles = {item["title"] for item in observations["confirmed_findings"]}
    assert "Emulated firmware service reachable for validation" in confirmed_titles
    assert any("http://127.0.0.1:8080/" in item for item in observations["evidence"])


def test_collect_artifact_observations_records_validated_lead_for_unreachable_probe_with_systemmode_fallback() -> None:
    from vulnagent.core.assessment import collect_artifact_observations

    observations = collect_artifact_observations(
        {
            "firmware_emulation_launch_user": (
                "EXECUTION_BACKEND: local\n"
                "SERVICE_TYPE: http\n"
                "PROBE_SERVICE_TYPE: http\n"
                "PROBE_PORT: 8080\n"
                "PROBE_SCHEME: http\n"
                "PROBE_ENDPOINT: http://127.0.0.1:8080/\n"
            ),
            "firmware_emulation_probe": (
                "SERVICE_TYPE: http\n"
                "ENDPOINT: http://127.0.0.1:8080/\n"
                "REACHABLE: false\n"
                "SUMMARY: unreachable\n"
                "DETAILS: connection refused\n"
            ),
            "firmware_emulation_launch_system": (
                "PACKAGE_PATH: E:/Temp/vulnagent/runs/demo/emulation/launch-system.txt\n"
                "QEMU_BINARY: C:/Program Files/qemu/qemu-system-mipsel.exe\n"
            ),
        }
    )

    validated_titles = {item["title"] for item in observations["validated_leads"]}
    assert "Firmware emulation validation requires a stronger runtime environment" in validated_titles


def test_collect_artifact_observations_records_validated_lead_for_systemmode_boundary_without_reachable_service() -> None:
    from vulnagent.core.assessment import collect_artifact_observations

    observations = collect_artifact_observations(
        {
            "firmware_emulation_launch_system": (
                "PACKAGE_PATH: E:/Temp/vulnagent/runs/demo/emulation/launch-system.txt\n"
                "QEMU_BINARY: C:/Program Files/qemu/qemu-system-mipsel.exe\n"
                "ATTEMPT_1_STDERR: Some ROM regions are overlapping\n"
            ),
        }
    )

    validated_titles = {item["title"] for item in observations["validated_leads"]}
    assert "Firmware emulation validation requires a stronger runtime environment" in validated_titles


def test_extract_latest_ai_text_skips_followup_nudge() -> None:
    from vulnagent.core.assessment import extract_latest_ai_text

    messages = [
        AIMessage(content="BusyBox 1.19.4 and admin:admin were identified in extracted strings."),
        HumanMessage(content="[SYSTEM] You must call a tool to proceed."),
    ]

    extracted = extract_latest_ai_text(messages)
    assert extracted == "BusyBox 1.19.4 and admin:admin were identified in extracted strings."


def test_normalize_ai_summary_text_strips_cheerleading_prefix() -> None:
    from vulnagent.core.assessment import normalize_ai_summary_text

    normalized = normalize_ai_summary_text(
        "Good - from the strings dump alone, this binary looks like an import-settings CGI handler."
    )
    assert normalized.startswith("from the strings dump alone")


def test_normalize_ai_summary_text_rejects_continuation_offer() -> None:
    from vulnagent.core.assessment import normalize_ai_summary_text

    normalized = normalize_ai_summary_text(
        "If you want, I can continue the firmware assessment and summarize findings such as:\n"
        "- filesystem layout\n"
        "- startup/init scripts\n"
        "If you want me to proceed, I'll pick new paths/files to inspect."
    )
    assert normalized == ""


def test_normalize_ai_summary_text_rejects_followup_plan_disguised_as_summary() -> None:
    from vulnagent.core.assessment import normalize_ai_summary_text

    normalized = normalize_ai_summary_text(
        "/etc/passwd doesn't contain readable text in this firmware image, so it may be generated at runtime.\n"
        "Next useful targets for firmware review would be:\n"
        "- /etc/shadow\n"
        "- /etc/init.d/\n"
        "If you want, I can continue enumerating."
    )
    assert normalized == ""


def test_is_actionable_validation_text_rejects_runtime_account_speculation() -> None:
    from vulnagent.core.assessment import is_actionable_validation_text

    assert not is_actionable_validation_text(
        "/etc/passwd didn't return readable text from this firmware image, so it's either absent, empty, "
        "binary-packed, or generated at runtime instead of stored there."
    )


def test_normalize_ai_summary_text_rejects_next_step_question() -> None:
    from vulnagent.core.assessment import normalize_ai_summary_text

    normalized = normalize_ai_summary_text(
        "OK. What would you like me to do next with the firmware?"
    )
    assert normalized == ""


def test_normalize_ai_summary_text_rejects_focus_menu_pitch() -> None:
    from vulnagent.core.assessment import normalize_ai_summary_text

    normalized = normalize_ai_summary_text(
        "If you want, I can continue with the firmware assessment and focus on things like:\n"
        "- startup/init scripts\n"
        "- web interface files\n"
        "- hardcoded credentials\n"
        "Just tell me what area you want next."
    )
    assert normalized == ""


def test_collect_artifact_observations_detects_versions_and_credentials() -> None:
    from vulnagent.core.assessment import collect_artifact_observations

    observations = collect_artifact_observations(
        {
            "file_identify": "embedded signatures:\n  - 0x00000040: SquashFS filesystem\n  - 0x00000064: gzip compressed data",
            "strings_extract": (
                "BusyBox v1.19.4\n"
                "lighttpd/1.4.28\n"
                "admin:admin\n"
                "/etc/shadow\n"
                "GoAhead-Webs\n"
                "miniupnpd\n"
            ),
        }
    )

    titles = {item["title"] for item in observations["findings"]}
    assert "Embedded SquashFS filesystem detected" in titles
    assert "Default or hardcoded credential indicator present" in titles
    assert "BusyBox version string present: 1.19.4" in titles
    assert any("admin:admin" in item for item in observations["evidence"])
    assert any("GoAhead-Webs" in item for item in observations["evidence"])
    assert any(target["title"] == "Review default credential path and login handlers" for target in observations["priority_targets"])


def test_collect_artifact_observations_detects_extracted_firmware_admin_surface() -> None:
    from vulnagent.core.assessment import collect_artifact_observations

    observations = collect_artifact_observations(
        {
            "binwalk_scan": (
                "DECIMAL       HEXADECIMAL     DESCRIPTION\n"
                "0              0x00000000     uImage header\n"
                "79891          0x00013813     JFFS2 filesystem marker\n"
                "99211          0x0001838b     JFFS2 filesystem marker\n"
                "1563254        0x0017da76     SquashFS filesystem\n"
                "1563350        0x0017dad6     XZ compressed data\n"
            ),
            "firmware_extract_summary": (
                "SQUASHFS_FOUND offset=0x0017da76\n"
                "ROOT_DIR: /bin\n"
                "ROOT_DIR: /etc_ro\n"
                "INTERESTING_PATH: /bin/goahead\n"
                "INTERESTING_PATH: /etc_ro/web/cgi-bin/upload.cgi\n"
                "INTERESTING_PATH: /etc_ro/web/d_telnet.asp\n"
                "TEXT_HIT: /etc_ro/rcS :: telnetd\n"
                "TEXT_HIT: /etc_ro/rcS :: goahead&\n"
                "TEXT_HIT: /etc_ro/inittab :: ttyS1::respawn:/bin/sh\n"
                "BINARY_STRING: /bin/goahead :: showSystemCommandASP\n"
                "BINARY_STRING: /bin/goahead :: upload.cgi\n"
                "BINARY_STRING: /bin/goahead :: form2Telnet.cgi\n"
            ),
            "firmware_read_path:/etc_ro/web/cgi-bin/upload.cgi": (
                "[auto-mode:strings]\n"
                "system\n"
                "/var/webupload\n"
                "nvram_set 2860 old_firmware \"%s\"\n"
                "upload.cgi.c\n"
            ),
            "firmware_read_path:/etc_ro/web/cgi-bin/upload_settings.cgi": (
                "[auto-mode:strings]\n"
                "tempnam\n"
                "system\n"
                "import\n"
                "import_5g\n"
                "cp %s /var/tmpcgi\n"
            ),
            "firmware_read_path:/sbin/chpasswd.sh": (
                "#!/bin/sh\n"
                "echo \"$1:$2\" > /tmp/tmpchpw\n"
                "chpasswd < /tmp/tmpchpw\n"
            ),
            "firmware_read_path:/etc_ro/web/cgi-bin/ExportSettings.sh": (
                "Content-Disposition: attachment; filename=\"config.img\"\n"
                "ralink_init show 2860 2>/dev/null\n"
                "ralink_init show rtdev 2>/dev/null\n"
            ),
            "firmware_read_path:/etc_ro/web/cgi-bin/reboot.sh": (
                "#!/bin/sh\n"
                "echo \"<body>rebooting</body>\"\n"
                "reboot &\n"
            ),
        }
    )

    titles = {item["title"] for item in observations["findings"]}
    assert "Embedded uImage firmware container detected" in titles
    assert "Embedded JFFS2 marker cluster detected" in titles
    assert "Embedded XZ-compressed payload detected" in titles
    assert "Boot script starts telnetd during initialization" in titles
    assert "Embedded GoAhead web administration binary present" in titles
    assert "Firmware web upload handlers present" in titles
    assert "GoAhead system-command management surface markers present" in titles
    assert "Upload handler binaries expose system/import execution markers" in titles
    assert "Password change helper pipes user-controlled credentials into chpasswd" in titles
    assert "Configuration export script exposes raw settings dump behavior" in titles
    assert "Web reboot handler script present" in titles
    assert any("showSystemCommandASP" in item for item in observations["evidence"])
    assert any("upload.cgi" in item for item in observations["evidence"])
    target_titles = {item["title"] for item in observations["priority_targets"]}
    assert "Map GoAhead command handlers and auth gates" in target_titles
    assert "Review firmware upload attack surface" in target_titles
    assert "Validate telnet enablement and management path" in target_titles
    assert "Review password update and credential management path" in target_titles
    assert "Review configuration export and secret exposure" in target_titles


def test_collect_artifact_observations_detects_telnet_bootstrap_and_nvram_account_flow() -> None:
    from vulnagent.core.assessment import collect_artifact_observations

    observations = collect_artifact_observations(
        {
            "firmware_read_path:/etc_ro/rcS": (
                "#!/bin/sh\n"
                "#for telnet debugging\n"
                "telnetd\n"
                "goahead&\n"
            ),
            "firmware_read_path:/etc_ro/web/d_telnet.asp": (
                "var telnet_en = \"<% getCfgGeneral(1, \"telnetEnabled\"); %>\";\n"
                "<form action=\"/goform/form2Telnet.cgi\" method=POST name=\"Telnet\">\n"
            ),
            "firmware_search:telnetEnabled": (
                "SEARCH_PATTERN: telnetEnabled\n"
                "MATCH: /etc_ro/web/d_telnet.asp [text] :: var telnet_en = \"<% getCfgGeneral(1, \"telnetEnabled\"); %>\";\n"
                "MATCH: /etc_ro/Wireless/RT2860AP/RT2860_default_vlan [text] :: telnetEnabled=0\n"
                "MATCH: /etc_ro/Wireless/RT2860AP/RT2860_factory_vlan [text] :: telnetEnabled=1\n"
                "MATCH_COUNT: 3\n"
            ),
            "firmware_read_path:/sbin/internet.sh": (
                "genSysFiles()\n"
                "{\n"
                "    login=`nvram_get 2860 Login`\n"
                "    pass=`nvram_get 2860 Password`\n"
                "    echo \"$login::0:0:Adminstrator:/:/bin/sh\" > /etc/passwd\n"
                "    chpasswd.sh $login $pass\n"
                "}\n"
            ),
            "firmware_search:/etc/passwd": (
                "SEARCH_PATTERN: /etc/passwd\n"
                "MATCH: /sbin/internet.sh [text] :: echo \"$login::0:0:Adminstrator:/:/bin/sh\" > /etc/passwd\n"
                "MATCH_COUNT: 1\n"
            ),
            "firmware_search:chpasswd.sh": (
                "SEARCH_PATTERN: chpasswd.sh\n"
                "MATCH: /sbin/chpasswd.sh [text] :: # usage: chpasswd.sh <user name> [<password>]\n"
                "MATCH: /sbin/internet.sh [text] :: chpasswd.sh $login $pass\n"
                "MATCH_COUNT: 2\n"
            ),
            "firmware_read_path:/sbin/chpasswd.sh": (
                "#!/bin/sh\n"
                "echo \"$1:$2\" > /tmp/tmpchpw\n"
                "chpasswd < /tmp/tmpchpw\n"
            ),
        }
    )

    titles = {item["title"] for item in observations["findings"]}
    assert "Factory configuration enables telnet management before login hardening" in titles
    assert "Boot script materializes an administrator shell account from NVRAM credentials" in titles
    assert any("telnetEnabled=1" in item for item in observations["evidence"])
    assert any("/sbin/internet.sh" in item for item in observations["evidence"])
    target_titles = {item["title"] for item in observations["priority_targets"]}
    assert "Trace NVRAM-backed admin credential generation" in target_titles


def test_collect_artifact_observations_preserves_systemmode_emulation_evidence() -> None:
    from vulnagent.core.assessment import collect_artifact_observations

    observations = collect_artifact_observations(
        {
            "firmware_emulation_launch_system": (
                "WORKSPACE_ROOT: E:/Temp/vulnagent/runs/demo\n"
                "PACKAGE_PATH: E:/Temp/vulnagent/runs/demo/emulation/launch-system.txt\n"
                "ARCHITECTURE: mips\n"
                "ENDIANNESS: little\n"
                "MACHINE: malta\n"
                "QEMU_BINARY: C:/Program Files/qemu/qemu-system-mipsel.exe\n"
                "KERNEL_CANDIDATE: E:/Temp/vulnagent/runs/demo/emulation/system/kernel.payload.bin\n"
                "KERNEL_CANDIDATE: E:/Temp/vulnagent/runs/demo/emulation/system/kernel.payload.elf\n"
                "ATTEMPT_1_COMMAND: C:/Program Files/qemu/qemu-system-mipsel.exe -nographic -monitor none -serial file:E:/Temp/vulnagent/runs/demo/emulation/system/serial.log -M malta -kernel E:/Temp/vulnagent/runs/demo/emulation/system/kernel.payload.elf\n"
                "ATTEMPT_1_STDERR: qemu-system-mipsel.exe: could not load kernel 'kernel.payload.bin': The image is not ELF\n"
                "ATTEMPT_3_STDERR: qemu-system-mipsel.exe: could not load kernel 'kernel.elf-candidate-1.bin': The image has incorrect endianness\n"
            ),
        }
    )

    titles = {item["title"] for item in observations["findings"]}
    assert "System-mode firmware emulation package prepared" in titles
    assert any("qemu-system-mipsel.exe" in item for item in observations["evidence"])
    assert any("kernel.payload.elf" in item for item in observations["evidence"])
    assert any("image is not ELF" in item for item in observations["evidence"])
    assert any("incorrect endianness" in item for item in observations["evidence"])
    assert any("system-mode" in item.lower() for item in observations["next_steps"])


def test_merge_report_text_reconciles_incomplete_structured_sections() -> None:
    from vulnagent.core.assessment import merge_report_text

    report = merge_report_text(
        "## Executive Summary\nExisting summary.\n\n"
        "## Unconfirmed Leads\n"
        "- Boot script starts telnetd during initialization\n",
        target="firmware.bin",
        scope="filesystem triage",
        provenance="artifact:firmware.bin",
        confirmed_findings=[],
        candidate_findings=[
            {"title": "Boot script starts telnetd during initialization"},
            {"title": "Boot script materializes an administrator shell account from NVRAM credentials"},
        ],
        evidence=["/etc_ro/rcS :: telnetd", "/sbin/internet.sh -> /etc/passwd"],
        priority_targets=[
            {
                "title": "Trace NVRAM-backed admin credential generation",
                "priority": "critical",
                "validation_focus": "Follow Login/Password into /etc/passwd generation.",
            },
        ],
        next_steps=["Review /sbin/internet.sh and linked web handlers."],
    )

    assert "## Executive Summary\nExisting summary." in report
    assert report.count("## Unconfirmed Leads") == 1
    assert "Boot script starts telnetd during initialization" in report
    assert "Boot script materializes an administrator shell account from NVRAM credentials" in report
    assert "## Priority Targets" in report
