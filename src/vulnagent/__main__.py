"""Allow `python -m vulnagent` to invoke the CLI."""

from vulnagent.cli import main

raise SystemExit(main())
