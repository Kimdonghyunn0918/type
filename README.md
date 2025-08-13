# 프로젝트명

Suricata IDS 로그를 수집해 머신러닝으로 악성 여부를 판단하고, 결과를 Elasticsearch에 저장하고 Slack으로 알림을 전송하는 자동화 시스템입니다.

---

## 📁 프로젝트 구조

```
final/
├── run.py                       # 메인 실행 스크립트
├── feature_engineering.py       # payload 기반 피처 생성 함수 정의
├── feature_weight_map.py        # 공격 유형별 피처 가중치 매핑
├── ml_alert_to_slack.py         # ML 결과를 Slack으로 전송
├── model/
│   └── score_based.pkl          # 학습된 ML 모델 번들
```

---

## 사용 방법

### 1. ML 추론 및 결과 저장 (Elasticsearch)

```bash
python run.py
```

- Suricata 로그 수집
- payload → 피처 추출 → 예측
- AbuseIPDB 조회
- Elasticsearch `ml-classified-*` 인덱스에 저장

### 2. Slack 알림 전송

```bash
python ml_alert_to_slack.py
```

- 최근 5분 내 alert 로그 검색
- Slack 채널로 요약 메시지 + 상세 JSON 전송
- 중복 전송 방지 캐시 적용

---

## 환경 변수 설정

| 변수명           | 설명                            | 기본값                    |
|------------------|----------------------------------|----------------------------|
| `ES_HOST`        | Elasticsearch 서버 주소         | `http://localhost:9200`   |
| `SOURCE_INDEX`   | 분석 대상 인덱스 이름           | `suricata-*`              |
| `SLACK_TOKEN`    | Slack 봇 토큰                   | (직접 지정 필요)          |
| `ABUSEIPDB_KEY`  | AbuseIPDB API 키                | (직접 지정 필요)          |

---

## 설치 라이브러리

```bash
pip install pandas scikit-learn elasticsearch slack_sdk joblib requests
```


---

## 팀소개

- 2025 중부대학교 정보보호학과 CCIT
- 팀원: 윤현식(팀장), 윤지현, 최경규, 김동현
