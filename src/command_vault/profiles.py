"""Read-only research metadata and revision-bound evidence references."""

import json

from .responses import (
    MitigationSummary, ProfileEvidence, ProfileSource, StageSummary,
    VulnerabilityProfile, VulnerabilityRecord,
    OperationalStageProfile, OperationalStageRecord, StageEdgeSummary,
)


_VULNERABILITY_COLUMNS = '''id,canonical_id,external_task_id,project_name,summary,
    summary_provenance,vulnerability_class,class_provenance,sanitizer,architecture,
    platform,subsystem,language,affected_symbols,introduced_revision,fixed_revision'''
_EVIDENCE_FILTER = '''(e.vulnerability_id=? OR e.writeup_id IN
    (SELECT writeup_id FROM writeup_vulnerabilities WHERE vulnerability_id=?))'''
_SOURCE_COLUMNS = '''w.id AS document_id,w.filename,w.domain,w.upstream_url,
    w.content_hash,s.name AS source_name,s.revision'''


def _source(row):
    document_id = row['document_id']
    return ProfileSource(
        document_id=document_id,
        reference=f'document:{document_id}@{document_id}.{row["content_hash"] or "legacy"}',
        filename=row['filename'], source_name=row['source_name'], domain=row['domain'],
        upstream_url=row['upstream_url'], revision=row['revision'],
    )


def _normalize_stage(value):
    return ' '.join(value.lower().split()) if value is not None else None


def _affected_symbols(value):
    if value is None or (isinstance(value, str) and not value.strip()):
        return []
    if not isinstance(value, str):
        raise ValueError('Affected symbols metadata must be a JSON string list or legacy text')
    try:
        symbols = json.loads(value)
    except (ValueError, RecursionError):
        # Brackets, braces, or quotes indicate structured metadata that must not
        # silently degrade into a purported legacy symbol after a parse failure.
        if value.lstrip().startswith(('[', '{', '"')):
            raise ValueError('Affected symbols metadata contains malformed JSON') from None
        return [value]
    if not isinstance(symbols, list) or any(not isinstance(symbol, str) or not symbol.strip() for symbol in symbols):
        raise ValueError('Affected symbols metadata must be a JSON list of nonblank strings')
    return symbols


class ResearchProfiles:
    def __init__(self, db):
        self.db = db

    def get_vulnerability(self, identifier, limit=25):
        if not isinstance(identifier, str) or not identifier.strip() or len(identifier) > 200:
            raise ValueError('Identifier must be nonblank text of at most 200 characters')
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError('Limit must be an integer between 1 and 100')
        identifier = identifier.strip()
        with self.db.read_snapshot():
            with self.db._get_connection() as conn:
                if conn.execute('PRAGMA user_version').fetchone()[0] < 2:
                    raise ValueError('Research profiles require database schema 2 or newer')
                parameters = (identifier, identifier)
                predicate = 'canonical_id=? COLLATE NOCASE OR external_task_id=? COLLATE NOCASE'
                total = conn.execute(f'SELECT COUNT(*) FROM vulnerabilities WHERE {predicate}', parameters).fetchone()[0]
                rows = conn.execute(f'''SELECT {_VULNERABILITY_COLUMNS} FROM vulnerabilities
                    WHERE {predicate}
                    ORDER BY canonical_id COLLATE NOCASE,external_task_id COLLATE NOCASE,id LIMIT ?''',
                    (*parameters, limit)).fetchall()
                remaining = limit
                truncated = total > len(rows)
                matches = []
                for row in rows:
                    vulnerability_id = row['id']
                    metadata = dict(row)
                    metadata['affected_symbols'] = _affected_symbols(metadata['affected_symbols'])
                    evidence, more = self._evidence(conn, vulnerability_id, remaining)
                    remaining -= len(evidence)
                    truncated = truncated or more
                    matches.append(VulnerabilityRecord(
                        **metadata, sources=self._sources(conn, vulnerability_id),
                        mitigations=self._mitigations(conn, vulnerability_id),
                        operational_stages=self._stages(conn, vulnerability_id), evidence=evidence,
                    ))
                return VulnerabilityProfile(identifier=identifier, matches=matches,
                                            total_matches=total, truncated=truncated)

    def get_operational_stage(self, identifier, domain=None, limit=25):
        if not isinstance(identifier, str) or not identifier.strip() or len(identifier) > 200:
            raise ValueError('Identifier must be nonblank text of at most 200 characters')
        if domain is not None and (not isinstance(domain, str) or not domain.strip() or len(domain) > 100):
            raise ValueError('Domain must be nonblank text of at most 100 characters')
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError('Limit must be an integer between 1 and 100')
        identifier = identifier.strip()
        normalized = _normalize_stage(identifier)
        domain = domain.strip() if domain is not None else None
        with self.db.read_snapshot():
            with self.db._get_connection() as conn:
                if conn.execute('PRAGMA user_version').fetchone()[0] < 2:
                    raise ValueError('Research profiles require database schema 2 or newer')
                # Connection-local normalization; no schema or stored values change.
                conn.create_function('_research_stage_normalize', 1, _normalize_stage, deterministic=True)
                predicate = '''(_research_stage_normalize(s.canonical_name)=? OR EXISTS (
                    SELECT 1 FROM stage_aliases a WHERE a.stage_id=s.id AND a.alias_normalized=?))'''
                parameters = [normalized, normalized]
                if domain is not None:
                    predicate += ' AND s.domain=? COLLATE NOCASE'
                    parameters.append(domain)
                total = conn.execute(f'SELECT COUNT(*) FROM operational_stages s WHERE {predicate}', parameters).fetchone()[0]
                rows = conn.execute(f'''SELECT s.id,s.canonical_name,s.domain,s.stage_class,s.description
                    FROM operational_stages s WHERE {predicate}
                    ORDER BY s.domain COLLATE NOCASE,s.canonical_name COLLATE NOCASE,s.id LIMIT ?''',
                    (*parameters, limit)).fetchall()
                matches = []
                truncated = total > len(rows)
                for row in rows:
                    matched_alias = None
                    if _normalize_stage(row['canonical_name']) != normalized:
                        alias = conn.execute('''SELECT alias FROM stage_aliases
                            WHERE stage_id=? AND alias_normalized=? ORDER BY alias COLLATE NOCASE,alias LIMIT ?''',
                            (row['id'], normalized, 1)).fetchone()
                        matched_alias = alias['alias'] if alias else None
                    evidence, more = self._evidence_for(
                        conn, 'e.stage_id=?', (row['id'],), limit, preferred_section=matched_alias,
                    )
                    truncated = truncated or more
                    matches.append(OperationalStageRecord(
                        **dict(row), matched_alias=matched_alias, aliases=self._aliases(conn, row['id']),
                        edges=self._edges(conn, row['id']), evidence=evidence,
                    ))
                # Apply the shared budget after ranking exact aliases across all
                # matches, so an earlier unrelated section cannot consume it.
                ranked = sorted(
                    (0 if match.matched_alias is not None and item.section == match.matched_alias else 1,
                     match_index, evidence_index)
                    for match_index, match in enumerate(matches)
                    for evidence_index, item in enumerate(match.evidence)
                )
                selected = {(match_index, evidence_index) for _, match_index, evidence_index in ranked[:limit]}
                truncated = truncated or len(ranked) > limit
                for match_index, match in enumerate(matches):
                    match.evidence = [item for evidence_index, item in enumerate(match.evidence)
                                      if (match_index, evidence_index) in selected]
                return OperationalStageProfile(identifier=identifier, domain=domain, matches=matches,
                                               total_matches=total, truncated=truncated)

    @staticmethod
    def _aliases(conn, stage_id):
        return [row[0] for row in conn.execute('''SELECT DISTINCT alias FROM stage_aliases
            WHERE stage_id=? AND alias IS NOT NULL AND alias<>?
            ORDER BY alias COLLATE NOCASE,alias''', (stage_id, ''))]

    @staticmethod
    def _edges(conn, stage_id):
        rows = conn.execute('''SELECT ? AS direction,e.relation AS relation,s.canonical_name AS stage,
            s.domain AS domain,e.evidence_reference AS evidence_reference FROM stage_edges e
            JOIN operational_stages s ON s.id=e.source_stage_id WHERE e.target_stage_id=?
            UNION SELECT ? AS direction,e.relation AS relation,s.canonical_name AS stage,
            s.domain AS domain,e.evidence_reference AS evidence_reference FROM stage_edges e
            JOIN operational_stages s ON s.id=e.target_stage_id WHERE e.source_stage_id=?
            ORDER BY direction,stage,domain,relation,evidence_reference''',
            ('incoming', stage_id, 'outgoing', stage_id))
        return [StageEdgeSummary(**dict(row)) for row in rows]

    @staticmethod
    def _sources(conn, vulnerability_id):
        rows = conn.execute(f'''SELECT {_SOURCE_COLUMNS} FROM writeups w
            LEFT JOIN source_collections s ON s.id=w.source_collection_id
            WHERE w.id IN (
                SELECT writeup_id FROM writeup_vulnerabilities WHERE vulnerability_id=?
                UNION SELECT writeup_id FROM evidence_links WHERE vulnerability_id=?
            ) ORDER BY s.name COLLATE NOCASE,w.filename COLLATE NOCASE,w.id''',
            (vulnerability_id, vulnerability_id))
        return [_source(row) for row in rows]

    @staticmethod
    def _mitigations(conn, vulnerability_id):
        rows = conn.execute('''SELECT DISTINCT m.canonical_name,m.raw_label,v.state,v.source_reference
            FROM vulnerability_mitigations v JOIN mitigations m ON m.id=v.mitigation_id
            WHERE v.vulnerability_id=? ORDER BY m.canonical_name COLLATE NOCASE,m.canonical_name,
            m.raw_label,v.state,v.source_reference''', (vulnerability_id,))
        return [MitigationSummary(**dict(row)) for row in rows]

    @staticmethod
    def _stages(conn, vulnerability_id):
        rows = conn.execute(f'''SELECT s.id,s.canonical_name,s.domain,s.stage_class,s.description,
            COUNT(DISTINCT COALESCE('chunk:'||e.chunk_id,'command:'||e.command_id,'script:'||e.script_id)) AS evidence_count
            FROM operational_stages s JOIN evidence_links e ON e.stage_id=s.id
            WHERE {_EVIDENCE_FILTER}
            GROUP BY s.id ORDER BY s.canonical_name COLLATE NOCASE,s.domain COLLATE NOCASE,s.id''',
            (vulnerability_id, vulnerability_id)).fetchall()
        result = []
        for row in rows:
            aliases = [alias[0] for alias in conn.execute(f'''SELECT DISTINCT a.alias
                FROM stage_aliases a JOIN evidence_links e ON e.stage_id=a.stage_id
                JOIN writeup_chunks c ON c.id=e.chunk_id AND c.writeup_id=e.writeup_id
                WHERE a.stage_id=? AND a.alias=c.section AND {_EVIDENCE_FILTER}
                ORDER BY a.alias COLLATE NOCASE,a.alias''',
                (row['id'], vulnerability_id, vulnerability_id))]
            result.append(StageSummary(**{key: row[key] for key in row.keys() if key != 'id'}, aliases=aliases))
        return result

    @staticmethod
    def _evidence(conn, vulnerability_id, limit):
        return ResearchProfiles._evidence_for(conn, _EVIDENCE_FILTER, (vulnerability_id, vulnerability_id), limit)

    @staticmethod
    def _evidence_for(conn, predicate, parameters, limit, preferred_section=None):
        rows = conn.execute(f'''SELECT * FROM (SELECT DISTINCT {_SOURCE_COLUMNS},
            CASE WHEN e.chunk_id IS NOT NULL THEN 'chunk'
                 WHEN e.command_id IS NOT NULL THEN 'command' ELSE 'script' END AS kind,
            COALESCE(e.chunk_id,e.command_id,e.script_id) AS artifact_id,
            e.evidence_role,e.assertion_provenance,e.validation_status,e.observed_outcome,
            stage.canonical_name AS stage,
            CASE WHEN e.chunk_id IS NOT NULL THEN c.section
                 WHEN e.command_id IS NOT NULL THEN cmd.source_section ELSE script.source_section END AS section
            FROM evidence_links e JOIN writeups w ON w.id=e.writeup_id
            LEFT JOIN source_collections s ON s.id=w.source_collection_id
            LEFT JOIN operational_stages stage ON stage.id=e.stage_id
            LEFT JOIN writeup_chunks c ON c.id=e.chunk_id
            LEFT JOIN commands cmd ON cmd.id=e.command_id
            LEFT JOIN scripts script ON script.id=e.script_id
            WHERE {predicate})
            ORDER BY CASE WHEN section=? THEN 0 ELSE 1 END,
                     document_id,kind,artifact_id,stage,evidence_role,assertion_provenance,
                     validation_status,observed_outcome,section LIMIT ?''',
            (*parameters, preferred_section, limit + 1)).fetchall()
        evidence = []
        for row in rows[:limit]:
            revision = f'{row["document_id"]}.{row["content_hash"] or "legacy"}'
            evidence.append(ProfileEvidence(
                reference=f'{row["kind"]}:{row["artifact_id"]}@{revision}', kind=row['kind'],
                evidence_role=row['evidence_role'], assertion_provenance=row['assertion_provenance'],
                validation_status=row['validation_status'], observed_outcome=row['observed_outcome'],
                stage=row['stage'], section=row['section'], source=_source(row),
            ))
        return evidence, len(rows) > limit
