"""模型管理工具 — 快速查看/添加/切换 LLM 供应商和模型映射.

Usage:
  python manage_models.py list               # 查看当前所有配置
  python manage_models.py add <name> <url> <key>  # 添加供应商
  python manage_models.py scan <name>         # 自动探测供应商的可用模型
  python manage_models.py use <purpose> <provider/model>  # 切换 purpose 指向
  python manage_models.py use all <provider/model>        # 全部切换
  python manage_models.py fallback <from_provider> <to_provider>  # 一键修复

Examples:
  python manage_models.py add deepseek https://api.deepseek.com/v1 sk-xxx
  python manage_models.py scan deepseek        # 自动列出 deepseek 的模型
  python manage_models.py use reasoning cliproxy/gpt-5.4
  python manage_models.py use all cliproxy/gpt-5.4-mini
  python manage_models.py fallback openai cliproxy   # 把所有 openai 的目的改到 cliproxy
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


def main() -> None:
    if len(sys.argv) < 2:
        _print_usage()
        return

    cmd = sys.argv[1].lower()

    if cmd == "list":
        cmd_list()
    elif cmd == "add":
        cmd_add(sys.argv[2:])
    elif cmd == "scan":
        cmd_scan(sys.argv[2:])
    elif cmd == "use":
        cmd_use(sys.argv[2:])
    elif cmd == "fallback":
        cmd_fallback(sys.argv[2:])
    elif cmd in ("help", "--help", "-h"):
        _print_usage()
    else:
        print(f"未知命令: {cmd}")
        _print_usage()


def _print_usage() -> None:
    print(__doc__)


def _get_config_path() -> Path:
    """Find the project settings.yaml."""
    path = _PROJECT_ROOT / ".myagents" / "settings.yaml"
    if not path.exists():
        print("错误: 找不到 .myagents/settings.yaml")
        sys.exit(1)
    return path


def _load_config() -> dict:
    import yaml
    path = _get_config_path()
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def _save_config(config: dict) -> None:
    import yaml
    path = _get_config_path()
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(config, f, allow_unicode=True, default_flow_style=False, sort_keys=False)


def _iter_env_files(project_root: Path | None = None) -> list[Path]:
    root = (project_root or _PROJECT_ROOT).resolve()
    search_roots: list[Path] = []
    current = root
    while True:
        search_roots.append(current)
        if current == current.parent:
            break
        current = current.parent

    env_files: list[Path] = []
    for search_root in reversed(search_roots):
        for name in (".env", ".env.local", "apikeys.txt"):
            candidate = search_root / name
            if candidate.exists():
                env_files.append(candidate)
    return env_files


def _parse_env_file(path: Path) -> dict[str, str]:
    parsed: dict[str, str] = {}
    try:
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[len("export ") :].strip()
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            if not key:
                continue
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
                value = value[1:-1]
            parsed[key] = value
    except OSError:
        return {}
    return parsed


def _load_runtime_env(project_root: Path | None = None) -> dict[str, str]:
    runtime_env = dict(os.environ)
    protected_keys = set(os.environ)
    for env_file in _iter_env_files(project_root):
        for key, value in _parse_env_file(env_file).items():
            if key in protected_keys:
                continue
            runtime_env[key] = value
    return runtime_env


def _resolve_provider_api_key(provider: dict, runtime_env: dict[str, str] | None = None) -> str:
    api_key = provider.get("api_key", "")
    if api_key:
        return api_key

    env_key = provider.get("api_key_env", "")
    if not env_key:
        return ""

    env = runtime_env if runtime_env is not None else _load_runtime_env()
    return env.get(env_key, "")


# ── Commands ────────────────────────────────────────────────────

def cmd_list() -> None:
    """列出当前所有配置."""
    config = _load_config()
    runtime_env = _load_runtime_env()

    print("\n=== 模型供应商 ===\n")
    providers = config.get("providers", {})
    for name, p in providers.items():
        has_key = bool(_resolve_provider_api_key(p, runtime_env))
        status = "有Key" if has_key else "无Key(不可用)"
        models = p.get("models", [])
        if not models:
            models_str = "(未配置, 用 python manage_models.py scan " + name + " 自动探测)"
        else:
            models_str = ", ".join(models)
        print(f"  [{name}]  {status}")
        print(f"    端点: {p.get('base_url', '?')}")
        print(f"    模型: {models_str}")
        print()

    print("=== Purpose 映射 ===\n")
    purposes = config.get("purposes", {})
    if not purposes:
        print("  (未配置)")
    for purpose, cfg in purposes.items():
        provider = cfg.get("provider", "?")
        model = cfg.get("model", "?")
        fallback = cfg.get("fallback_provider", "")
        fb_str = f"  → 备用: {fallback}/{cfg.get('fallback_model', '')}" if fallback else ""
        print(f"  {purpose:12s} → {provider}/{model}{fb_str}")
    print()

    # 检查是否有不可用的映射
    _check_availability(config, runtime_env)


def cmd_add(args: list[str]) -> None:
    """添加新的模型供应商.

    Usage: python manage_models.py add <name> <base_url> <api_key> [models...]
    """
    if len(args) < 3:
        print("用法: python manage_models.py add <名称> <base_url> <api_key> [模型1 模型2 ...]")
        print("示例: python manage_models.py add deepseek https://api.deepseek.com/v1 sk-xxx")
        return

    name = args[0]
    base_url = args[1]
    api_key = args[2]
    model_list = args[3:] if len(args) > 3 else []

    config = _load_config()
    if "providers" not in config:
        config["providers"] = {}

    config["providers"][name] = {
        "base_url": base_url,
        "api_key": api_key,
    }
    if model_list:
        config["providers"][name]["models"] = model_list

    _save_config(config)

    print(f"已添加供应商: {name}")
    print(f"  端点: {base_url}")
    print(f"  Key: {api_key[:12]}...")
    if model_list:
        print(f"  模型: {', '.join(model_list)}")
    else:
        print(f"  提示: 模型列表为空, 可以用 python manage_models.py scan {name} 自动探测")


def cmd_scan(args: list[str]) -> None:
    """自动探测供应商的可用模型列表.

    调用 /v1/models 端点, 自动提取模型名称并更新配置.
    """
    if not args:
        print("用法: python manage_models.py scan <供应商名称>")
        return

    name = args[0]
    config = _load_config()
    provider = config.get("providers", {}).get(name)

    if not provider:
        print(f"供应商 '{name}' 未配置, 请先用 add 命令添加")
        return

    base_url = provider.get("base_url", "")
    api_key = _resolve_provider_api_key(provider, _load_runtime_env())

    if not api_key:
        print(f"供应商 '{name}' 没有配置 API Key, 无法探测")
        return

    print(f"正在从 {base_url}/models 探测可用模型...")

    try:
        import urllib.request
        import json

        req = urllib.request.Request(
            f"{base_url}/models",
            headers={"Authorization": f"Bearer {api_key}"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())

        # OpenAI 格式: {"data": [{"id": "model-name", ...}, ...]}
        models = []
        if isinstance(data, dict) and "data" in data:
            for item in data["data"]:
                model_id = item.get("id", "")
                if model_id:
                    models.append(model_id)
        elif isinstance(data, list):
            models = [m.get("id", str(m)) for m in data]

        if models:
            config["providers"][name]["models"] = models
            _save_config(config)
            print(f"探测到 {len(models)} 个模型:")
            for m in models:
                print(f"  - {m}")
        else:
            print("未探测到任何模型, 返回数据:", json.dumps(data, indent=2)[:500])
    except Exception as e:
        print(f"探测失败: {e}")
        print("提示: 确保供应商端点的 /models 路径可访问")


def cmd_use(args: list[str]) -> None:
    """切换 purpose 映射.

    Usage:
      python manage_models.py use reasoning cliproxy/gpt-5.4
      python manage_models.py use all cliproxy/gpt-5.4-mini
    """
    if len(args) < 2:
        print("用法: python manage_models.py use <purpose|all> <provider/model>")
        print("示例: python manage_models.py use reasoning cliproxy/gpt-5.4")
        print("      python manage_models.py use all cliproxy/gpt-5.4-mini")
        return

    purpose = args[0]
    provider_model = args[1]

    if "/" not in provider_model:
        print("错误: 格式应为 '<provider>/<model>', 如 'cliproxy/gpt-5.4'")
        return

    provider, model = provider_model.split("/", 1)
    config = _load_config()

    targets = (
        list(config.get("purposes", {}).keys())
        if purpose == "all"
        else [purpose]
    )

    if "purposes" not in config:
        config["purposes"] = {}

    for p in targets:
        if p not in config["purposes"]:
            config["purposes"][p] = {}
        config["purposes"][p]["provider"] = provider
        config["purposes"][p]["model"] = model

    _save_config(config)

    for p in targets:
        print(f"  {p} → {provider}/{model}")
    print("已保存, 重启服务生效")


def cmd_fallback(args: list[str]) -> None:
    """一键切换: 把所有指向 A 的 purpose 改为指向 B 的对应模型.

    Usage: python manage_models.py fallback openai cliproxy
    """
    if len(args) < 2:
        print("用法: python manage_models.py fallback <从> <到>")
        print("示例: python manage_models.py fallback openai cliproxy")
        return

    from_provider = args[0]
    to_provider = args[1]

    config = _load_config()
    to_models = config.get("providers", {}).get(to_provider, {}).get("models", [])
    if not to_models:
        print(f"警告: 目标供应商 '{to_provider}' 没有配置模型列表")
        print(f"请先运行: python manage_models.py scan {to_provider}")

    purposes = config.get("purposes", {})
    changed = 0
    for purpose, cfg in purposes.items():
        if cfg.get("provider") == from_provider:
            cfg["provider"] = to_provider
            # 尝试智能匹配模型
            old_model = cfg.get("model", "")
            # 如果目标有同名模型就用, 否则用第一个
            matched = None
            for m in to_models:
                if old_model in m or m in old_model:
                    matched = m
                    break
            cfg["model"] = matched or (to_models[0] if to_models else old_model)
            changed += 1
            print(f"  {purpose}: {from_provider}/{old_model} → {to_provider}/{cfg['model']}")

    if changed == 0:
        print(f"没有 purpose 指向 {from_provider}, 无需更改")
        return

    _save_config(config)
    print(f"\n已修改 {changed} 个 purpose, 保存并重启服务生效")


def _check_availability(config: dict, runtime_env: dict[str, str] | None = None) -> None:
    """检查 purpose 映射的可达性."""
    providers = config.get("providers", {})
    purposes = config.get("purposes", {})

    env = runtime_env if runtime_env is not None else _load_runtime_env()
    issues = []
    for purpose, cfg in purposes.items():
        provider = cfg.get("provider", "")
        pconfig = providers.get(provider, {})
        has_key = bool(_resolve_provider_api_key(pconfig, env))
        if not has_key:
            issues.append(f"  {purpose} → {provider} (无API Key, 不可用)")

    if issues:
        print("⚠ 发现问题:")
        for i in issues:
            print(i)
        print(f"  修复: python manage_models.py fallback <from> <有Key的供应商>")
        print()


if __name__ == "__main__":
    main()
