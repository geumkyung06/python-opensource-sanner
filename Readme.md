# NVD 기반 Python 패키지 취약점 검사

Python 3.10 이상, 표준 라이브러리만 사용합니다. OSV API는 사용하지 않습니다.

## 실행

패키지 하나를 온라인 NVD에서 조회:

```sh
python3 /Users/lgk/opensource/scanner.py --package requests 2.19.1 --json nvd-result.json
```

프로젝트 가상환경을 활성화한 뒤 설치된 패키지 검사:

```sh
python /Users/lgk/opensource/scanner.py --installed --json nvd-installed-result.json
```

버전이 고정된 목록 검사:

```sh
python3 /Users/lgk/opensource/scanner.py -r /path/to/requirements.txt
```

가지고 있는 NVD JSON에서만 검사 (인터넷 불필요):

```sh
python3 /Users/lgk/opensource/scanner.py --installed --nvd-json /Users/lgk/opensource/nvdcve-2.0-recent.json --json nvd-local-result.json
```

`--installed`는 실행하는 Python 환경의 설치 메타데이터에서 이름·버전을 수집합니다.
requirements는 단순 `name==version`, 빈 줄, 주석만 지원합니다. 범위, extras, 환경 마커,
다른 파일 포함, URL, 해시 옵션은 판단 보류합니다. 패키지를 설치하거나 변경하지 않습니다.

## NVD에서 찾는 방식

1. 설치된 Python 배포 패키지의 이름·버전을 읽습니다.
2. `cpe_mappings.json`에 확인된 제품 연결 정보가 있으면 NVD CVE API의
   `virtualMatchString`으로 해당 제품의 CVE를 조회하고, `keywords` 검색어로 CPE 미등록 후보도 수집합니다.
3. 매핑이 없으면 `keywordSearch`로 패키지 이름을 검색합니다. 검색된 CVE는 후보로만 표시하고
   제품 확인 전에는 취약하다고 확정하지 않습니다. 검색 결과가 없어도 판단 보류입니다.
4. NVD `configurations`의 제품 CPE, `vulnerable`, 버전 범위의 포함·제외 경계를 대조합니다.
5. CVE ID, NVD 분석 상태, 판정 근거, 원본 CVE 정보를 결과 JSON에 저장합니다.

로컬 JSON 모드는 파일의 CPE 또는 설명 속 패키지 이름으로 후보를 찾은 뒤 같은 판정을 적용합니다.
NVD API/피드 2.0 형식(`vulnerabilities[].cve`)을 받습니다.
파일명에 `recent`가 들어간 피드는 전체 취약점 이력이 아닙니다. 해당 파일에 오래된 CVE가 없다면
탐지할 수 없으므로 미발견을 안전으로 해석하지 마세요. 결과에는 입력 경로와 피드 시각이 기록됩니다.

## CPE 매핑 범위

초기 매핑은 실제 NVD 응답과 프로젝트 참조 링크를 확인한 두 패키지입니다.

| PyPI | NVD CPE 제품 | 확인 근거 |
|---|---|---|
| requests | `a:python:requests` | CVE-2018-18074 |
| pip | `a:pypa:pip` | CVE-2023-5752 |

다른 패키지는 NVD 제품의 공급자·프로젝트 참조를 확인한 뒤 매핑에 추가하세요.
패키지 이름이 CPE 제품명과 같다는 이유만으로 자동 연결하지 않습니다.
`--mapping /path/to/mappings.json`으로 별도 매핑 파일을 선택할 수 있습니다.
등록 형식은 기본 `cpe_mappings.json`을 참고하세요. `cpes`는 제품별 전체 CPE 문자열 목록이고,
버전 이후 필드는 모두 `*`여야 합니다. 여러 제품 별칭을 확인했다면 목록에 함께 넣습니다.
`evidence`에는 확인에 사용한 NVD/프로젝트 링크를 기록합니다.
`keywords`는 CPE가 없는 CVE를 보완 검색하는 문자열 목록입니다. 생략하면 패키지 이름으로 검색합니다.

## 판정과 제한

- `affected`: 확인된 제품의 CPE와 영향 버전 조건이 일치함. 실제 공격 가능성을 확정하지 않음.
- `not_found`: 지정한 CPE/입력 데이터 범위에서 일치 항목이 발견되지 않음. 안전 보장이 아님.
- `unknown`: 제품 연결 미확인, 불충분한 적용 정보, 미지원 조건, 조회 실패 또는 잘린 검색 결과.

`vulnStatus`가 `Analyzed`인 CVE만 고르지 않습니다. `Modified`, `Deferred` 등도 적용 조건이
있으면 검사하고, `Rejected`는 제외합니다. 분석 상태 자체는 취약 여부가 아닙니다.

최초 구현은 점으로 구분한 숫자 릴리스 버전(예: 2.19.1)과 단순 OR 조건을 지원합니다.
문자열 순서로 버전을 비교하지 않습니다. prerelease/post/dev/local 버전, CPE 이스케이프,
추가 플랫폼/에디션 조건, AND/NOT 조건 등은 판단 보류합니다.
온라인 모드는 CPE 조회와 키워드 조회를 합칩니다. CPE가 없는 검색 후보는 판단 보류하며,
검색어로도 찾지 못한 CVE나 등록되지 않은 제품 별칭은 누락될 수 있습니다. 이 도구는 완전한 취약점 감사 도구가 아닙니다.

결과 JSON의 `vulnerabilities`에는 영향 버전 일치와 판단 보류 후보가 함께 들어갑니다.
각 CVE의 `status`를 구분해서 읽으세요. `candidates_checked`에는 범위 밖/거부된 CVE도 포함됩니다.
패키지에 확정 일치와 미해결 후보가 함께 있으면 패키지 상태는 `affected`, `needs_review`는 true입니다.

종료 코드: 0 = 조회 범위 내 미발견, 1 = 영향 버전 일치, 2 = 오류/판단 보류/needs_review 포함.
JSON 출력 파일이 이미 있으면 덮어씁니다.

온라인 요청은 최소 6.1초 간격이며 30초 타임아웃을 사용합니다. 연결 실패나 제한 응답은
판단 보류로 표시합니다. 선택적으로 `NVD_API_KEY` 환경 변수의 키를 요청 헤더에 사용합니다.
키는 결과에 저장하지 않습니다. 온라인 조회 시 CPE 또는 패키지 검색어가 NVD에 전송됩니다.
페이지를 순회하되 질의별 후보 한도는 기본 200개입니다. `--max-results`로 늘릴 수 있으며,
한도 초과 시 `truncated`와 `needs_review`를 기록합니다.

SPDX 생성, 내부에 복사된 코드/JAR 검사, 실행 경로 분석은 이번 범위에 포함하지 않습니다.
사설 패키지/로컬 수정본은 같은 이름·버전의 공개 패키지와 코드가 다를 수 있습니다.
기존 Readme와 NVD 원본 파일은 수정하지 않았습니다.
기존 `example-result.json`, `installed-result.json`은 이전 OSV 실행 결과이며 현재 결과가 아닙니다.
새 검증 결과는 `nvd-`로 시작하는 파일에 저장합니다.

## 검증

```sh
cd /Users/lgk/opensource
python3 -m unittest -v
```

NVD 공식 API 설명: https://nvd.nist.gov/developers/vulnerabilities
NVD 적용 조건 설명: https://nvd.nist.gov/vuln/Vulnerability-Detail-Pages
