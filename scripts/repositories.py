"""Shared repository configuration helpers for benchmark scripts."""

from __future__ import annotations

import dataclasses
from pathlib import Path


@dataclasses.dataclass(frozen=True)
class RepositoryConfig:
    """A repository checkout that can satisfy benchmark cases."""

    repository: str
    path: Path


def normalize_repository_id(repository: str) -> str:
    """Normalize a repository ID for case-insensitive matching."""
    return repository.strip().lower()


def parse_repo_configs(
    repo_specs: list[str] | None, openclaw_repo: str | None = None
) -> dict[str, RepositoryConfig]:
    """Parse --repo OWNER/NAME=PATH arguments into a repository map."""
    raw_specs = list(repo_specs or [])
    if openclaw_repo:
        raw_specs.append(f"openclaw/openclaw={openclaw_repo}")

    repo_configs: dict[str, RepositoryConfig] = {}
    for spec in raw_specs:
        repository, separator, repo_path = spec.partition("=")
        repository = repository.strip()
        repo_path = repo_path.strip()
        if separator != "=" or not repository or not repo_path:
            raise ValueError(
                f"invalid --repo value {spec!r}; expected OWNER/NAME=/path/to/repo"
            )

        normalized = normalize_repository_id(repository)
        config = RepositoryConfig(repository=repository, path=Path(repo_path).resolve())
        existing = repo_configs.get(normalized)
        if existing and existing.path != config.path:
            raise ValueError(
                f"repository {repository!r} was configured multiple times "
                f"with different paths: {existing.path} and {config.path}"
            )
        repo_configs[normalized] = config

    return repo_configs
