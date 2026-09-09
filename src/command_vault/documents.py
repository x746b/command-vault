"""Section-aware evidence extraction. Fenced text is data, never executed."""

import re

PARSER_VERSION = 'sections-v2'
MAX_CHUNK_CHARS = 3000
CHUNK_OVERLAP = 200


def sections(text: str):
    heading = 'Introduction'
    lines = []
    start = 1
    fence = None
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        marker = re.match(r'^(`{3,}|~{3,})', stripped)
        if marker:
            current = marker.group(1)
            if fence is None:
                fence = current
            elif current[0] == fence[0] and len(current) >= len(fence):
                fence = None
        match = re.match(r'^#{1,6}\s+(.+?)\s*#*$', stripped) if fence is None else None
        if match:
            if lines:
                yield {'section': heading, 'content': '\n'.join(lines).strip(), 'line_start': start}
            heading = match.group(1)
            lines = []
            start = number + 1
        else:
            lines.append(line)
    if lines:
        yield {'section': heading, 'content': '\n'.join(lines).strip(), 'line_start': start}


def knowledge_chunks(text: str):
    result = []
    for section in sections(text):
        body = section['content']
        if not body or len(body) < 30:
            continue
        offset = 0
        while offset < len(body):
            end = min(offset + MAX_CHUNK_CHARS, len(body))
            if end < len(body):
                boundary = body.rfind('\n', offset + MAX_CHUNK_CHARS // 2, end)
                if boundary >= 0:
                    end = boundary + 1
            part = body[offset:end].strip()
            if part:
                result.append({'section': section['section'], 'content': part,
                               'chunk_index': len(result)})
            if end == len(body):
                break
            offset = max(offset + 1, end - CHUNK_OVERLAP)
    return result
