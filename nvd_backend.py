"""Conservative NVD 2.0 lookup. Unverified identities are never confirmed."""
import json
import os
import re
import time
import urllib.parse
import urllib.request
from pathlib import Path

API_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'


def cpe_parts(value):
    # Escaped delimiters/wildcards require a full CPE matcher; do not guess.
    if not isinstance(value, str) or '\\' in value:
        return None
    parts = value.split(':')
    return parts if len(parts) == 13 and parts[:2] == ['cpe', '2.3'] else None


def load_mappings(path):
    data = json.loads(Path(path).read_text(encoding='utf-8'))
    if not isinstance(data, dict):
        raise ValueError('CPE 매핑은 JSON 객체여야 합니다.')
    for name, entry in data.items():
        if not isinstance(entry, dict) or not isinstance(entry.get('cpes'), list) or not entry['cpes']:
            raise ValueError(f'{name}: cpes 목록이 필요합니다.')
        if not isinstance(entry.get('keywords', []), list) or not all(isinstance(k, str) and k.strip() for k in entry.get('keywords', [])):
            raise ValueError(f'{name}: keywords는 검색 문자열 목록이어야 합니다.')
        for cpe in entry['cpes']:
            parts = cpe_parts(cpe)
            if (not parts or parts[2] != 'a' or
                not all(re.fullmatch(r'[a-z0-9_.-]+', p) and p != '-' for p in parts[3:5]) or
                parts[5:] != ['*'] * 8):
                raise ValueError(f'{name}: 제품 단위 CPE가 필요합니다: {cpe}')
    return data


def extract_cves(data):
    if not isinstance(data, dict) or not isinstance(data.get('vulnerabilities'), list):
        raise ValueError('NVD 2.0 vulnerabilities 배열이 필요합니다.')
    records = []
    for item in data['vulnerabilities']:
        cve = item.get('cve') if isinstance(item, dict) else None
        if not isinstance(cve, dict) or not isinstance(cve.get('id'), str):
            raise ValueError('NVD CVE 레코드가 잘못되었습니다.')
        records.append(cve)
    return records


class NvdClient:
    def __init__(self):
        self.last_request = None

    def fetch(self, params):
        if self.last_request is not None:
            time.sleep(max(0, 6.1 - (time.monotonic() - self.last_request)))
        self.last_request = time.monotonic()
        headers = {'User-Agent': 'simple-python-nvd-scanner/2.0'}
        if os.environ.get('NVD_API_KEY'):
            headers['apiKey'] = os.environ['NVD_API_KEY']
        req = urllib.request.Request(API_URL + '?' + urllib.parse.urlencode(params), headers=headers)
        with urllib.request.urlopen(req, timeout=30) as response:
            return json.load(response)


def fetch_cves(params, fetch, limit=200):
    records, start = {}, 0
    while True:
        data = fetch({**params, 'startIndex': start, 'resultsPerPage': min(200, limit - start)})
        page = extract_cves(data)
        total = data.get('totalResults')
        if not isinstance(total, int) or total < 0 or data.get('startIndex') != start:
            raise ValueError('NVD 페이지 정보가 잘못되었습니다.')
        for cve in page:
            records[cve['id']] = cve
        start += len(page)
        if start >= total:
            return list(records.values()), False
        if not page:
            raise ValueError('NVD가 빈 중간 페이지를 반환했습니다.')
        if start >= limit:
            return list(records.values()), True


def matches_in(node):
    if not isinstance(node, dict):
        raise ValueError('NVD configuration 형식 오류')
    yield from node.get('cpeMatch', [])
    for key in ('nodes', 'children'):
        for child in node.get(key, []):
            yield from matches_in(child)


def identity(match):
    parts = cpe_parts(match.get('criteria'))
    return tuple(parts[2:5]) if parts else None


def numeric_version(value):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9]+(?:\.[0-9]+)*', value):
        raise ValueError('숫자 릴리스 버전이 아님')
    parts = [int(x) for x in value.split('.')]
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


def version_match(match, version):
    parts = cpe_parts(match.get('criteria'))
    if not parts or any(p != '*' for p in parts[6:]):
        return None  # update, target_sw, platform, edition etc. not collected
    try:
        current = numeric_version(version)
        if parts[5] != '*' and current != numeric_version(parts[5]):
            return False
        for key, compare in (
            ('versionStartIncluding', lambda a, b: a >= b),
            ('versionStartExcluding', lambda a, b: a > b),
            ('versionEndIncluding', lambda a, b: a <= b),
            ('versionEndExcluding', lambda a, b: a < b),
        ):
            if key in match and not compare(current, numeric_version(match[key])):
                return False
        return True
    except ValueError:
        return None


def evaluate(node, identities, version):
    if node.get('negate') or node.get('operator', 'OR') != 'OR':
        return None  # AND/platform combinations require environment evidence
    values = []
    for match in node.get('cpeMatch', []):
        if identity(match) in identities and match.get('vulnerable') is True:
            values.append(version_match(match, version))
        else:
            values.append(None)
    for key in ('nodes', 'children'):
        values.extend(evaluate(child, identities, version) for child in node.get(key, []))
    if any(v is True for v in values):
        return True
    if values and all(v is False for v in values):
        return False
    return None


def assess(cve, cpes, version):
    if cve.get('vulnStatus') == 'Rejected':
        return 'excluded', '거부된 CVE'
    if not cpes:
        return 'unknown', 'PyPI 패키지와 CPE의 연결이 확인되지 않았습니다.'
    identities = {tuple(cpe_parts(cpe)[2:5]) for cpe in cpes}
    relevant = [config for config in cve.get('configurations', [])
                if any(identity(m) in identities for m in matches_in(config))]
    if not relevant:
        return 'unknown', '해당 제품의 CPE 적용 정보가 없습니다.'
    values = [evaluate(config, identities, version) for config in relevant]
    if any(v is True for v in values):
        return 'affected', '확인된 제품 CPE와 NVD 영향 버전 조건이 일치합니다.'
    if all(v is False for v in values):
        return 'not_affected', '수집된 해당 제품 CPE의 영향 버전 범위 밖입니다.'
    return 'unknown', '복합 조건, 환경 조건 또는 지원하지 않는 버전 표기로 판단할 수 없습니다.'


class NvdScanner:
    def __init__(self, mappings, local_path=None, fetch=None, limit=200):
        self.mappings, self.limit = mappings, limit
        self.fetch = fetch or NvdClient().fetch
        self.cache = {}
        self.local = None
        self.timestamp = None
        if local_path:
            data = json.loads(Path(local_path).read_text(encoding='utf-8'))
            self.local = extract_cves(data)
            self.timestamp = data.get('timestamp')

    def candidates(self, name, cpes):
        if self.local is not None:
            ids = {tuple(cpe_parts(c)[2:5]) for c in cpes}
            pattern = re.compile(r'(?<![\w-])' + re.escape(name) + r'(?![\w-])', re.I)
            records = []
            for cve in self.local:
                has_cpe = any(identity(m) in ids for c in cve.get('configurations', []) for m in matches_in(c))
                text = ' '.join(d.get('value', '') for d in cve.get('descriptions', []))
                if has_cpe or pattern.search(text):
                    records.append(cve)
            return records, False
        records, truncated = {}, False
        # Query mapped identities directly; keywords alone are only discovery hints.
        queries = [{'virtualMatchString': cpe} for cpe in cpes]
        keywords = self.mappings.get(name, {}).get('keywords', [name])
        queries += [{'keywordSearch': term, 'keywordExactMatch': ''} for term in keywords]
        if not queries:
            queries = [{'keywordSearch': name}]
        for params in queries:
            key = tuple(params.items())
            if key not in self.cache:
                self.cache[key] = fetch_cves(params, self.fetch, self.limit)
            page, partial = self.cache[key]
            truncated |= partial
            records.update((c['id'], c) for c in page)
        return list(records.values()), truncated

    def query(self, name, version):
        mapping = self.mappings.get(name, {})
        cpes = mapping.get('cpes', [])
        records, truncated = self.candidates(name, cpes)
        findings = []
        for cve in records:
            status, reason = assess(cve, cpes, version)
            if status in ('affected', 'unknown'):
                findings.append({'id': cve['id'], 'status': status, 'reason': reason,
                                 'vulnStatus': cve.get('vulnStatus'),
                                 'url': 'https://nvd.nist.gov/vuln/detail/' + cve['id'], 'cve': cve})
        pending = truncated or not cpes or any(f['status'] == 'unknown' for f in findings)
        affected = any(f['status'] == 'affected' for f in findings)
        return {'status': 'affected' if affected else 'unknown' if pending else 'not_found',
                'needs_review': bool(pending), 'truncated': truncated,
                'reason': ('후보 조회 한도 초과: 결과가 일부입니다.' if truncated else
                           'CPE 매핑 미등록: 검색 결과는 후보이며 취약 판정이 아닙니다.' if not cpes else
                           '지정 CPE/입력 데이터 범위의 결과입니다. CPE 미등록 CVE나 다른 제품 별칭은 누락될 수 있습니다.'),
                'matched_cpes': cpes, 'mapping_evidence': mapping.get('evidence', []),
                'candidates_checked': len(records), 'vulnerabilities': findings}
