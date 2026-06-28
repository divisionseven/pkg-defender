"""pkgd db group and subcommands."""

from __future__ import annotations

import asyncio
import contextlib
import gzip
import hashlib
import logging
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any, cast

import click

from pkg_defender.cli.common import console
from pkg_defender.cli.group import ManagerGroup
from pkg_defender.cli.main import cli

from .._exit_codes import (
    EXIT_DB_ERROR as _EXIT_DB_ERROR,
)
from .._exit_codes import (
    EXIT_GENERAL_ERROR as _EXIT_GENERAL_ERROR,
)

logger = logging.getLogger(__name__)


@cli.group(cls=ManagerGroup, name="db")
def db_group() -> None:
    """Database management commands."""
    pass


@db_group.command(name="snapshot")
@click.option(
    "--download",
    "-d",
    is_flag=True,
    help="Download snapshot with SHA256 verification (GitHub Releases or custom URL)",
)
@click.option(
    "--verify",
    "-v",
    is_flag=True,
    help="Verify local database integrity with SHA256",
)
@click.option(
    "--latest",
    "-l",
    is_flag=True,
    help="Show latest available snapshot version on GitHub",
)
@click.option(
    "--force",
    "-f",
    is_flag=True,
    help="Force replacement of existing database",
)
@click.pass_context
def db_snapshot(
    ctx: click.Context,
    download: bool,
    verify: bool,
    latest: bool,
    force: bool,
) -> None:
    """Database snapshot management.

    Download pre-built snapshots from GitHub Releases with SHA256 verification,
    or verify the integrity of an existing local database.

    Examples:

    \b
        pkgd db snapshot --download
        pkgd db snapshot --download --force
        pkgd db snapshot --verify
        pkgd db snapshot --latest

    EXIT CODES:
        0    Success
        1    General error
        7    Verification failed

    ENVIRONMENT:
        PKGD_CONFIG_PATH    Config file location
        PKGD_DATABASE_PATH  Custom database path

    FILES:
        ~/.local/share/pkg-defender/threats.db    Threat database

    \f
    """
    from pkg_defender.cli.common import get_db_path
    from pkg_defender.db.schema import init_db

    async def fetch_latest_release() -> dict[str, Any] | None:
        import aiohttp

        try:
            result = subprocess.run(
                ["git", "remote", "get-url", "origin"],
                capture_output=True,
                text=True,
                check=True,
                timeout=10,
            )
            remote_url = result.stdout.strip()
            if remote_url.endswith(".git"):
                remote_url = remote_url[:-4]
            if "github.com/" in remote_url:
                repo_path = remote_url.split("github.com/")[-1]
            else:
                repo_path = remote_url.split(":")[-1]
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            click.echo(
                "Error: Could not determine GitHub repository. "
                "Check that the git remote 'origin' points to a GitHub repository.",
                err=True,
            )
            return None

        api_url = f"https://api.github.com/repos/{repo_path}/releases/latest"
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            try:
                async with session.get(api_url, headers=headers) as resp:
                    if resp.status == 404:
                        click.echo(
                            "Error: No snapshot release found on GitHub (404). "
                            "Snapshot releases are published automatically by CI. "
                            "Run 'pkgd intel sync' to build the database locally.",
                            err=True,
                        )
                        return None
                    if resp.status != 200:
                        click.echo(f"Error: GitHub API returned status {resp.status}", err=True)
                        return None
                    json_data: Any = await resp.json()
                    return cast(dict[str, Any], json_data)
            except aiohttp.ClientError as e:
                click.echo(f"Error fetching release: {e}", err=True)
                return None

    async def download_and_verify_snapshot(
        db_path: Path,
        custom_url: str | None = None,
    ) -> bool:
        import aiohttp

        # NEW: If custom_url is provided, use it directly instead of GitHub API discovery
        if custom_url:
            console.print(f"Downloading snapshot from custom URL: {custom_url}...")
            timeout = aiohttp.ClientTimeout(total=300)

            # Stream compressed snapshot to a temp file (bounded memory)
            custom_compressed_tmp: str | None = None
            try:
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    try:
                        async with session.get(custom_url) as resp:
                            if resp.status != 200:
                                click.echo(
                                    f"Error: Download returned status {resp.status}",
                                    err=True,
                                )
                                return False
                            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                                async for chunk, _ in resp.content.iter_chunks():
                                    if chunk:
                                        tmp.write(chunk)
                                custom_compressed_tmp = tmp.name
                    except aiohttp.ClientError as e:
                        click.echo(f"Error downloading: {e}", err=True)
                        return False

                # SHA256 verification via companion .sha256 file
                sha_url = custom_url + ".sha256"
                console.print("Verifying SHA256 checksum...")
                async with aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as session:
                    try:
                        async with session.get(sha_url) as resp:
                            if resp.status == 200:
                                sha_content = await resp.text()
                                expected_sha = sha_content.strip().split()[0]
                            else:
                                click.echo(
                                    f"Error: Could not fetch SHA256 checksum "
                                    f"from {sha_url} (HTTP {resp.status}). "
                                    f"Refusing to use unverified snapshot.",
                                    err=True,
                                )
                                return False
                    except aiohttp.ClientError as e:
                        click.echo(
                            f"Error: Could not fetch SHA256 checksum "
                            f"from {sha_url}: {e}. "
                            f"Refusing to use unverified snapshot.",
                            err=True,
                        )
                        return False

                sha256_hash = hashlib.sha256()
                with open(custom_compressed_tmp, "rb") as f:
                    while True:
                        chunk = f.read(65536)
                        if not chunk:
                            break
                        sha256_hash.update(chunk)
                actual_sha = sha256_hash.hexdigest()

                if actual_sha != expected_sha:
                    console.print("[red]SHA256 verification FAILED![/red]")
                    console.print(f"  Expected: {expected_sha}")
                    console.print(f"  Actual:   {actual_sha}")
                    return False

                console.print("[green]SHA256 verified \u2713[/green]")

                if db_path.exists() and not force:
                    click.echo(
                        "Database already exists. Use --force to replace, or download will be skipped.",
                        err=True,
                    )
                    return False

                if db_path.exists():
                    backup_path = db_path.with_suffix(".db.backup")
                    console.print(f"Backing up existing database to {backup_path}...")
                    try:
                        subprocess.run(["trash", str(db_path)], check=True, timeout=5)
                    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
                        db_path.rename(backup_path)

                console.print(f"Writing database to {db_path}...")

                # Stream-decompress from temp file to atomic write path
                fd, final_tmp = tempfile.mkstemp(
                    dir=db_path.parent,
                    prefix=".snapshot.",
                    suffix=".tmp",
                )
                try:
                    with os.fdopen(fd, "wb") as tmp_file, gzip.open(custom_compressed_tmp, "rb") as gz_in:
                        while True:
                            chunk = gz_in.read(65536)
                            if not chunk:
                                break
                            tmp_file.write(chunk)
                    os.replace(final_tmp, db_path)
                except Exception:
                    with contextlib.suppress(FileNotFoundError):
                        os.unlink(final_tmp)
                    raise

                try:
                    conn = init_db(db_path)
                    count = conn.execute("SELECT COUNT(*) FROM threats").fetchone()
                    count_val = count[0] if count else 0
                    conn.close()
                    console.print(f"[green]Database updated: {count_val} threats[/green]")
                except Exception as e:
                    click.echo(f"Error verifying database: {e}", err=True)
                    return False

                return True
            finally:
                if custom_compressed_tmp is not None:
                    with contextlib.suppress(OSError):
                        os.unlink(custom_compressed_tmp)

        # Existing GitHub API flow follows (unchanged)
        release = await fetch_latest_release()
        if not release:
            return False

        db_asset = None
        sha_asset = None
        for asset in release.get("assets", []):
            name = asset.get("name", "")
            if name.endswith(".db.gz"):
                db_asset = asset
            elif name.endswith(".sha256"):
                sha_asset = asset

        if not db_asset:
            click.echo(
                "Error: No database asset found in latest release. "
                "Check GitHub release tags or configure a custom URL.",
                err=True,
            )
            return False

        db_url = db_asset.get("browser_download_url")
        if not db_url:
            click.echo("Error: Could not get download URL", err=True)
            return False

        console.print(f"Downloading {db_asset.get('name')}...")
        timeout = aiohttp.ClientTimeout(total=300)

        # Stream compressed snapshot to a temp file (bounded memory)
        compressed_tmp: str | None = None
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                try:
                    async with session.get(db_url) as resp:
                        if resp.status != 200:
                            click.echo(f"Error: Download returned status {resp.status}", err=True)
                            return False
                        with tempfile.NamedTemporaryFile(delete=False) as tmp:
                            async for chunk, _ in resp.content.iter_chunks():
                                if chunk:
                                    tmp.write(chunk)
                            compressed_tmp = tmp.name
                except aiohttp.ClientError as e:
                    click.echo(f"Error downloading: {e}", err=True)
                    return False

            # SHA256 verification (read temp file in chunks)
            if sha_asset:
                sha_url = sha_asset.get("browser_download_url")
                console.print("Verifying SHA256 checksum...")
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
                    try:
                        async with session.get(sha_url) as resp:
                            if resp.status == 200:
                                sha_content = await resp.text()
                                expected_sha = sha_content.strip().split()[0]
                            else:
                                expected_sha = None
                    except aiohttp.ClientError:
                        expected_sha = None

                sha256_hash = hashlib.sha256()
                with open(compressed_tmp, "rb") as f:
                    while True:
                        chunk = f.read(65536)
                        if not chunk:
                            break
                        sha256_hash.update(chunk)
                actual_sha = sha256_hash.hexdigest()

                if expected_sha:
                    if actual_sha != expected_sha:
                        console.print("[red]SHA256 verification FAILED![/red]")
                        console.print(f"  Expected: {expected_sha}")
                        console.print(f"  Actual:   {actual_sha}")
                        return False
                    console.print("[green]SHA256 verified \u2713[/green]")

            if db_path.exists() and not force:
                click.echo("Database already exists. Use --force to replace, or download will be skipped.", err=True)
                return False

            if db_path.exists():
                backup_path = db_path.with_suffix(".db.backup")
                console.print(f"Backing up existing database to {backup_path}...")
                try:
                    subprocess.run(["trash", str(db_path)], check=True, timeout=5)
                except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
                    db_path.rename(backup_path)

            console.print(f"Writing database to {db_path}...")

            # Stream-decompress from temp file to atomic write path
            fd, final_tmp = tempfile.mkstemp(
                dir=db_path.parent,
                prefix=".snapshot.",
                suffix=".tmp",
            )
            try:
                with os.fdopen(fd, "wb") as tmp_file, gzip.open(compressed_tmp, "rb") as gz_in:
                    while True:
                        chunk = gz_in.read(65536)
                        if not chunk:
                            break
                        tmp_file.write(chunk)
                os.replace(final_tmp, db_path)
            except Exception:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(final_tmp)
                raise

            try:
                conn = init_db(db_path)
                count = conn.execute("SELECT COUNT(*) FROM threats").fetchone()
                count_val = count[0] if count else 0
                conn.close()
                console.print(f"[green]Database updated: {count_val} threats[/green]")
            except Exception as e:
                click.echo(f"Error verifying database: {e}", err=True)
                return False

            return True
        finally:
            if compressed_tmp is not None:
                with contextlib.suppress(OSError):
                    os.unlink(compressed_tmp)

    if latest:
        console.print("Fetching latest snapshot info...")
        release = asyncio.run(fetch_latest_release())
        if release:
            tag = release.get("tag_name", "unknown")
            published = release.get("published_at", "unknown")
            console.print(f"Latest snapshot: {tag}")
            console.print(f"Published: {published}")

            console.print("Assets:")
            for asset in release.get("assets", []):
                size_mb = asset.get("size", 0) / (1024 * 1024)
                console.print(f"  - {asset.get('name')} ({size_mb:.1f} MB)")
        else:
            click.echo(
                "Error: Could not retrieve snapshot release info. "
                "Check your internet connection or run 'pkgd intel sync' "
                "to build the database locally.",
                err=True,
            )
        return

    if verify:
        db_path = get_db_path()
        if not db_path.exists():
            click.echo(
                "Error: No local database found. Run 'pkgd setup' to initialize your local database.",
                err=True,
            )
            raise SystemExit(_EXIT_GENERAL_ERROR)

        console.print(f"Verifying {db_path}...")

        sha256_hash = hashlib.sha256()
        with open(db_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256_hash.update(chunk)

        result = sha256_hash.hexdigest()
        console.print(f"SHA256: {result}")

        try:
            conn = init_db(db_path)
            conn.execute("SELECT COUNT(*) FROM threats").fetchone()
            conn.close()
            console.print("[green]Database integrity: OK[/green]")
        except Exception as e:
            console.print(f"[red]Database integrity check FAILED: {e}[/red]")
            raise SystemExit(_EXIT_DB_ERROR) from None

        return

    if download:
        from pkg_defender.config import load_config

        _cfg = load_config()
        custom_snapshot_url = _cfg.database.snapshot_url
        db_path = get_db_path()
        success = asyncio.run(
            download_and_verify_snapshot(
                db_path,
                custom_url=custom_snapshot_url or None,
            )
        )
        if success:
            console.print("[green]Snapshot updated successfully![/green]")
        else:
            console.print("[yellow]Download failed or skipped.[/yellow]\nFalling back to local build...")
            console.print("Run 'pkgd intel sync' to build local database.")
        return

    click.echo(ctx.get_help())


@db_group.command(name="verify")
def db_verify() -> None:
    """Verify local database integrity and report summary.

    Runs SQLite PRAGMA integrity_check to detect page-level corruption,
    then reports threat count, last sync time, and file size.

    EXIT CODES:
        0   Database is healthy
        1   Corruption detected or database not found
    \f

    Examples:

    \b
        pkgd db verify
    """
    from pkg_defender.cli.common import get_db_path

    db_path = get_db_path()

    if not db_path.exists():
        click.echo(
            f"Error: Database not found at {db_path}. Run 'pkgd db download' to fetch the latest snapshot.",
            err=True,
        )
        raise SystemExit(_EXIT_GENERAL_ERROR)

    click.echo(f"Verifying database at {db_path}...", err=True)

    from pkg_defender.db.schema import get_connection

    try:
        conn = get_connection(db_path)
    except Exception as e:
        click.echo(
            f"Error: Could not open database: {e}. Run 'pkgd db verify' to check database integrity.",
            err=True,
        )
        raise SystemExit(_EXIT_GENERAL_ERROR) from None

    try:
        # --- PRAGMA integrity_check ---
        integrity_rows = conn.execute("PRAGMA integrity_check").fetchall()
        integrity_ok = len(integrity_rows) == 1 and integrity_rows[0][0] == "ok"

        if integrity_ok:
            click.echo("PRAGMA integrity_check: ok")
        else:
            click.echo("PRAGMA integrity_check: FAILED")
            for row in integrity_rows:
                click.echo(f"  Corruption: {row[0]}")
            conn.close()
            raise SystemExit(_EXIT_GENERAL_ERROR)

        click.echo("")
        click.echo("Database Summary:")

        # --- Threat count ---
        try:
            count_row = conn.execute("SELECT COUNT(*) FROM threats").fetchone()
            threat_count = count_row[0] if count_row else 0
            click.echo(f"  Threat records:  {threat_count:,}")
        except Exception:
            logger.debug("db info: threat count query failed")
            click.echo("  Threat records:  N/A (threats table not accessible)")

        # --- Last sync ---
        try:
            sync_row = conn.execute("SELECT last_sync FROM feed_state ORDER BY last_sync DESC LIMIT 1").fetchone()
            last_sync = sync_row[0] if sync_row else "never"
            click.echo(f"  Last sync:       {last_sync}")
        except Exception:
            logger.debug("db info: last sync query failed")
            click.echo("  Last sync:       N/A (feed_state table not accessible)")

        # --- Schema version ---
        try:
            from pkg_defender.db.schema import get_schema_version

            schema_version = get_schema_version(conn)
            click.echo(f"  Schema version:  {schema_version}")
        except Exception:
            logger.debug("db info: schema version query failed")
            click.echo("  Schema version:  N/A (schema_version table not accessible)")

        # --- File size ---
        try:
            file_size_bytes = db_path.stat().st_size
            if file_size_bytes < 1024:
                file_size_str = f"{file_size_bytes} B"
            elif file_size_bytes < 1024 * 1024:
                file_size_str = f"{file_size_bytes / 1024:.1f} KB"
            else:
                file_size_str = f"{file_size_bytes / (1024 * 1024):.1f} MB"
            click.echo(f"  File size:       {file_size_str}")
        except OSError:
            click.echo("  File size:       N/A")

        conn.close()
    except SystemExit:
        conn.close()
        raise
    except Exception as e:
        click.echo(f"Error during verification: {e}", err=True)
        conn.close()
        raise SystemExit(_EXIT_GENERAL_ERROR) from None
