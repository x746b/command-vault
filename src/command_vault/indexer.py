"""Indexer for processing writeup directories."""

import logging
import time
from pathlib import Path
from typing import Optional

from .database import Database
from .parser import WriteupParser
from .security import SecurityFilter
from .models import IndexResult, Command, ShellType

logger = logging.getLogger(__name__)


class Indexer:
    """Indexes writeup directories into the database."""

    def __init__(
        self,
        db: Database,
        security_filter: Optional[SecurityFilter] = None
    ):
        self.db = db
        self.security = security_filter or SecurityFilter()
        self.parser = WriteupParser(self.security)

    def index_directory(
        self,
        directory: str,
        force_rebuild: bool = False,
        skip_existing: bool = False,
        source_dir: Optional[str] = None
    ) -> IndexResult:
        """
        Index all markdown files in a directory.

        Args:
            directory: Path to directory containing writeups
            force_rebuild: If True, clear existing data first
            skip_existing: If True, skip files that are already indexed
            source_dir: Directory type ('unified', 'boxes', 'challenges', 'sherlocks')

        Returns:
            IndexResult with statistics
        """
        start_time = time.time()
        errors = []
        files_processed = 0
        files_skipped = 0
        commands_extracted = 0
        scripts_extracted = 0
        chunks_extracted = 0

        path = Path(directory)
        if not path.exists():
            return IndexResult(
                files_processed=0,
                commands_extracted=0,
                scripts_extracted=0,
                errors=[f"Directory not found: {directory}"],
                duration_seconds=0
            )

        # Find all markdown files
        md_files = list(path.glob("**/*.md"))
        logger.info(f"Found {len(md_files)} markdown files in {directory}")

        # Get already indexed files if skipping existing
        indexed_files = self.db.get_indexed_filenames() if skip_existing else set()

        for md_file in md_files:
            # Skip if already indexed
            if skip_existing and md_file.name in indexed_files:
                files_skipped += 1
                continue

            try:
                result = self.index_file(
                    str(md_file),
                    force_rebuild=force_rebuild,
                    source_dir=source_dir
                )
                files_processed += 1
                commands_extracted += result['commands']
                scripts_extracted += result['scripts']
                chunks_extracted += result['chunks']

                if files_processed % 50 == 0:
                    logger.info(f"Processed {files_processed} files...")

            except Exception as e:
                error_msg = f"Error processing {md_file.name}: {str(e)}"
                logger.error(error_msg)
                errors.append(error_msg)

        duration = time.time() - start_time

        if skip_existing and files_skipped > 0:
            logger.info(f"Skipped {files_skipped} already indexed files")

        logger.info(
            f"Indexing complete: {files_processed} files, "
            f"{commands_extracted} commands, {scripts_extracted} scripts, "
            f"{chunks_extracted} chunks in {duration:.2f}s"
        )

        return IndexResult(
            files_processed=files_processed,
            commands_extracted=commands_extracted,
            scripts_extracted=scripts_extracted,
            chunks_extracted=chunks_extracted,
            errors=errors,
            duration_seconds=duration
        )

    def index_file(
        self,
        filepath: str,
        force_rebuild: bool = False,
        source_dir: Optional[str] = None
    ) -> dict:
        """
        Index a single writeup file.

        Args:
            filepath: Path to the markdown file
            force_rebuild: If True, clear existing data for this writeup
            source_dir: Directory type ('unified', 'boxes', 'challenges', 'sherlocks')

        Returns:
            Dict with counts: {commands, scripts, chunks}
        """
        # Parse the file with appropriate settings based on source_dir
        # 'unified' dir enables full content scanning and content-based type detection
        full_scan = (source_dir == 'unified')
        writeup, commands, scripts, chunks = self.parser.parse_file(
            filepath,
            full_scan=full_scan,
            source_dir=source_dir
        )

        # Insert or update writeup
        writeup_id = self.db.insert_writeup(writeup)

        # Always clear existing data to prevent duplicates on re-index
        self.db.clear_writeup_data(writeup_id)

        # Insert commands
        command_count = 0
        for cmd in commands:
            # Get or create tool
            tool_id = None
            if cmd.tool_name:
                tool_id = self.db.get_or_create_tool(cmd.tool_name)

            # Create command model
            command = Command(
                tool_id=tool_id,
                tool_name=cmd.tool_name,
                writeup_id=writeup_id,
                raw_command=cmd.raw_command,
                command_template=cmd.template,
                flags_used=cmd.flags,
                purpose=cmd.context[:500] if cmd.context else None,
                context=cmd.context,
                source_section=cmd.section,
                shell_type=cmd.shell_type
            )

            self.db.insert_command(command)
            command_count += 1

        # Insert scripts
        script_count = 0
        for script in scripts:
            script.writeup_id = writeup_id
            self.db.insert_script(script)
            script_count += 1

        # Insert chunks
        chunk_count = 0
        for chunk in chunks:
            self.db.insert_chunk(
                writeup_id=writeup_id,
                section=chunk['section'],
                content=chunk['content'],
                chunk_index=chunk['chunk_index']
            )
            chunk_count += 1

        return {
            'commands': command_count,
            'scripts': script_count,
            'chunks': chunk_count
        }

    def index_all(
        self,
        directories: dict[str, str],
        force_rebuild: bool = False,
        add_new_only: bool = False
    ) -> IndexResult:
        """
        Index multiple directories.

        Args:
            directories: Dict of {name: path} for directories
            force_rebuild: If True, reset database first
            add_new_only: If True, only add new files (skip existing)

        Returns:
            Combined IndexResult
        """
        if force_rebuild:
            logger.info("Force rebuild requested - resetting database")
            self.db.reset()
            self.security.clear_log()
        elif add_new_only:
            existing_count = self.db.get_writeup_count()
            logger.info(f"Adding new writeups only (currently {existing_count} indexed)")

        total_result = IndexResult(
            files_processed=0,
            commands_extracted=0,
            scripts_extracted=0,
            errors=[],
            duration_seconds=0
        )

        start_time = time.time()

        for name, path in directories.items():
            logger.info(f"Indexing {name}: {path}")
            result = self.index_directory(
                path,
                force_rebuild=False,
                skip_existing=add_new_only,
                source_dir=name  # 'unified', 'boxes', 'challenges', 'sherlocks'
            )

            total_result.files_processed += result.files_processed
            total_result.commands_extracted += result.commands_extracted
            total_result.scripts_extracted += result.scripts_extracted
            total_result.chunks_extracted += result.chunks_extracted
            total_result.errors.extend(result.errors)

        total_result.duration_seconds = time.time() - start_time

        # Log redaction summary
        redaction_summary = self.security.get_redaction_summary()
        if redaction_summary['total'] > 0:
            logger.info(f"Security redactions: {redaction_summary['total']} items")
            for rtype, count in redaction_summary['by_type'].items():
                logger.info(f"  - {rtype}: {count}")

        return total_result
