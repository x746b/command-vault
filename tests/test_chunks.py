"""Tests for writeup chunk indexing and FTS search."""

import pytest
import tempfile
import os

from command_vault.database import Database
from command_vault.models import Writeup, WriteupType


@pytest.fixture
def db():
    """Create a temporary database for testing."""
    fd, path = tempfile.mkstemp(suffix='.db')
    os.close(fd)
    database = Database(path)
    yield database
    os.unlink(path)


@pytest.fixture
def sample_writeup(db):
    """Insert a sample writeup and return its ID."""
    writeup = Writeup(
        filename='Authority.md',
        filepath='/writeups/Authority.md',
        writeup_type=WriteupType.BOX,
        title='Authority',
    )
    return db.insert_writeup(writeup)


class TestChunkInsertAndSearch:
    def test_insert_and_search_chunk(self, db, sample_writeup):
        """Insert a chunk and find it via FTS."""
        db.insert_chunk(
            writeup_id=sample_writeup,
            section='389/tcp - LDAP',
            content='We discover that NTLM relay to LDAP is possible due to signing not being enforced.',
            chunk_index=0
        )

        results = db.search_chunks('NTLM relay')
        assert len(results) == 1
        assert 'NTLM relay' in results[0].content
        assert results[0].source['filename'] == 'Authority.md'

    def test_search_no_results(self, db, sample_writeup):
        """Search for something that doesn't exist."""
        db.insert_chunk(
            writeup_id=sample_writeup,
            section='Enumeration',
            content='Running port scan to identify open services on the target.',
            chunk_index=0
        )

        results = db.search_chunks('Kerberoasting')
        assert len(results) == 0

    def test_multi_word_search(self, db, sample_writeup):
        """Multi-word queries should match documents with all words."""
        db.insert_chunk(
            writeup_id=sample_writeup,
            section='AD Exploitation',
            content='ADCS misconfiguration allows ESC8 attack via web enrollment endpoint.',
            chunk_index=0
        )

        results = db.search_chunks('ADCS ESC8')
        assert len(results) == 1

    def test_clear_writeup_data_clears_chunks(self, db, sample_writeup):
        """Clearing writeup data should also clear chunks."""
        db.insert_chunk(
            writeup_id=sample_writeup,
            section='Test',
            content='Some test content that is long enough to pass the length check.',
            chunk_index=0
        )

        # Verify chunk exists
        results = db.search_chunks('test content')
        assert len(results) == 1

        # Clear writeup data
        db.clear_writeup_data(sample_writeup)

        # Chunk should be gone
        results = db.search_chunks('test content')
        assert len(results) == 0

    def test_stats_include_chunks(self, db, sample_writeup):
        """Stats should include chunk count."""
        db.insert_chunk(
            writeup_id=sample_writeup,
            section='Test',
            content='First chunk of prose content for statistics testing.',
            chunk_index=0
        )
        db.insert_chunk(
            writeup_id=sample_writeup,
            section='Test',
            content='Second chunk of prose content for statistics testing.',
            chunk_index=1
        )

        stats = db.get_stats()
        assert stats.chunks is not None
        assert stats.chunks['total'] == 2

    def test_search_with_writeup_type_filter(self, db, sample_writeup):
        """Should filter chunks by writeup type."""
        db.insert_chunk(
            writeup_id=sample_writeup,
            section='Foothold',
            content='Exploiting the vulnerability to gain initial access to the target system.',
            chunk_index=0
        )

        # Should find with matching type
        results = db.search_chunks('vulnerability', writeup_type='box')
        assert len(results) == 1

        # Should not find with non-matching type
        results = db.search_chunks('vulnerability', writeup_type='sherlock')
        assert len(results) == 0
