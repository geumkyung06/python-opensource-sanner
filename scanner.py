"""NVD-based Python package scanner. Python 3.10+, standard library only."""
import argparse
import importlib.metadata
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from nvd_backend import API_URL, NvdScanner, load_mappings
NAME = r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?"
PIN = re.compile(rf"^({NAME})==([A-Za-z0-9][A-Za-z0-9.!+_-]*)$")


def normalize(name):
    return re.sub(r"[-_.]+", "-", name).lower()

def package(name, version, source):
    return {"name": normalize(name), "version": version, "source": source}


def read_requirements(path):
    packages, unresolved = [], []
    for number, line in enumerate(Path(path).read_text(encoding="utf-8-sig").splitlines(), 1):
        line = re.split(r"\s+#", line, maxsplit=1)[0].strip()
        if not line or line.startswith("#"):
            continue
        source = f"{path}:{number}"
        match = PIN.fullmatch(line)
        if match:
            packages.append(package(*match.groups(), source))
        else:
            unresolved.append({"name": None, "version": None, "source": source,
                               "status": "unknown", "reason": "단순 name==version 형식만 지원합니다. 설치 환경을 검사하세요."})
    return packages, unresolved


def installed_packages():
    packages, unresolved = [], []
    for dist in importlib.metadata.distributions():
        name, version = dist.metadata.get("Name"), dist.version
        if name and version:
            packages.append(package(name, version, "installed"))
        else:
            unresolved.append({"name": name, "version": version, "source": "installed",
                               "status": "unknown", "reason": "패키지 이름 또는 버전 메타데이터가 없습니다."})
    return packages, unresolved


def scan(packages, query):
    results, cache = [], {}
    for item in packages:
        key = (item["name"], item["version"])
        if key not in cache:
            try:
                cache[key] = query(*key)
            except (OSError, ValueError, TypeError, KeyError) as exc:
                cache[key] = {"status": "unknown", "needs_review": True, "reason": f"NVD 조회/분석 실패: {exc}"}
        results.append({**item, **cache[key]})
    return results


def render(report):
    labels = {"affected": "영향 버전 일치", "not_found": "알려진 취약점 미발견", "unknown": "판단 보류"}
    for result in report["results"]:
        print(f"[{labels[result['status']]}] {result['name'] or '(입력 확인 필요)'} {result['version'] or ''} ({result['source']})")
        if result.get("reason"):
            print(f"  {result['reason']}")
        for vuln in result.get("vulnerabilities", []):
            print(f"  [{labels[vuln['status']]}] {vuln['id']} (NVD: {vuln.get('vulnStatus')})")
            print(f"  {vuln['url']}")
    print("\n" + " / ".join(f"{labels[key]}: {value}" for key, value in report["counts"].items()))
    pending = sum(bool(r.get("needs_review")) for r in report["results"])
    if pending:
        print(f"추가 검토 필요: {pending}개 패키지 (영향 버전 일치 항목에도 미해결 후보가 있을 수 있습니다.)")
    print("미발견은 안전을 보장하지 않습니다. 설치 여부와 실제 실행 여부는 다릅니다.")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Python 패키지 이름·버전으로 NVD 취약점 조회 (내장 라이브러리 검사 제외)")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--package", nargs=2, metavar=("NAME", "VERSION"), help="패키지 이름과 정확한 버전")
    group.add_argument("--installed", action="store_true", help="이 스크립트를 실행하는 Python 환경 검사")
    group.add_argument("-r", "--requirements", type=Path, help="단순 name==version 목록 검사")
    parser.add_argument("--json", type=Path, dest="output", help="JSON 결과 저장")
    parser.add_argument("--nvd-json", type=Path, help="온라인 대신 로컬 NVD 2.0 JSON 검사")
    parser.add_argument("--mapping", type=Path, default=Path(__file__).with_name("cpe_mappings.json"), help="확인된 PyPI→CPE 매핑")
    parser.add_argument("--max-results", type=int, default=200, help="온라인 질의별 후보 한도 (기본 200)")
    args = parser.parse_args(argv)
    if args.max_results < 1:
        parser.error("--max-results는 양수여야 합니다.")
    try:
        if args.package:
            name, version = args.package
            if not PIN.fullmatch(f"{name}=={version}"):
                parser.error("유효한 패키지 이름과 정확한 버전을 입력하세요. 범위와 와일드카드는 지원하지 않습니다.")
            packages, unresolved = [package(name, version, "explicit")], []
        elif args.installed:
            packages, unresolved = installed_packages()
        else:
            packages, unresolved = read_requirements(args.requirements)
        backend = NvdScanner(load_mappings(args.mapping), args.nvd_json, limit=args.max_results)
        print("NVD 검사 중... 온라인 요청은 최소 6.1초 간격입니다." if not args.nvd_json else "로컬 NVD JSON 검사 중...", file=sys.stderr)
        results = scan(packages, backend.query) + unresolved
        if not results:
            results = [{"name": None, "version": None, "source": "input", "status": "unknown", "reason": "검사할 패키지가 없습니다."}]
        counts = {status: sum(r["status"] == status for r in results) for status in ("affected", "not_found", "unknown")}
        report = {"schema_version": 2, "checked_at": datetime.now(timezone.utc).isoformat(),
                  "database": "NVD", "api_url": API_URL,
                  "input_source": str(args.nvd_json.resolve()) if args.nvd_json else API_URL,
                  "feed_timestamp": backend.timestamp, "python_executable": sys.executable,
                  "scope": "NVD CPE/version match within configured identities or local feed; no bundled-code or runtime-reachability analysis",
                  "counts": counts, "results": results}
        render(report)
        if args.output:
            args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return 2 if counts["unknown"] or any(r.get("needs_review") for r in results) else 1 if counts["affected"] else 0
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"파일 처리 실패: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
