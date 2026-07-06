# vulnagent

Standalone operator-driven vulnerability research agent for binaries, firmware,
repro labs, and user-directed live targets.

## Quickstart

```powershell
python -m vulnagent.cli --status
python -m vulnagent.cli --check-deps
python -m vulnagent.cli --target ".\samples\firmware.bin" --scope "filesystem triage"
```

## Configuration

- shared private switchboard: `../.myagents/settings.yaml`
- project config: `config/settings.yaml`
- project local override: `config/settings.local.yaml`
- auto-loaded private env files: `../apikeys.txt`, `../.env`, `../.env.local`
- user config: `~/.vulnagent/settings.yaml`
- runtime state: `.vulnagent/`

Copy [config/settings.example.yaml](config/settings.example.yaml) to
`config/settings.yaml` and set one or more provider API keys with environment
variables such as `OPENAI_API_KEY` or entries in the auto-loaded `apikeys.txt`.

Recommended split:

- keep shared provider/model routing in `../.myagents/settings.yaml`
- keep machine-local secrets in `apikeys.txt` or project overrides in `config/settings.local.yaml`
- keep committed defaults in `config/settings.example.yaml` or a non-secret `config/settings.yaml`

## CLI

```powershell
python -m vulnagent.cli --help
python -m vulnagent.cli --status
python -m vulnagent.cli --check-deps
python -m vulnagent.cli --target ".\artifact.bin" --scope "local ELF triage" --json
```
