# 프로젝트명

Suricata IDS 로그를 수집해 머신러닝으로 악성 여부를 판단하고, 결과를 Elasticsearch에 저장하고 Slack으로 알림을 전송하는 자동화 시스템입니다.

---

## 📁 프로젝트 구조

```
ml/
├── main.py # ML 추론 + Elasticsearch 저장
├── feature_engineering.py # payload 기반 피처 생성
├── feature_weight_map.py # 공격 유형별 피처 가중치
├── ml_alert_to_slack.py # Slack 알림 전송 스크립트
├── model/
│ └── score_based.pkl # 학습된 ML 모델 번들
sensor/
├── filebeat/
│ └── filebeat.yml # Filebeat 설정
├── suricata/
│ ├── suricata.yml # IDS 설정
│ └── rules/local.rules # IDS 룰셋
server/ # 로그 저장 및 시각화 서버 (ELK)
├── elasticsearch/config/elasticsearch.yml
├── kibana/config/kibana.yml
└── logstash/pipeline/suricata-pipeline.conf
```

---

## 🔹 실행 흐름
1. Suricata – 네트워크 트래픽 분석 및 로그 생성
2. Filebeat – Suricata 로그 수집
3. Logstash – 로그 파싱 및 Elasticsearch로 전송
4. ML 파이프라인 (`main.py`) – 악성 여부 예측, AbuseIPDB 조회, Elasticsearch 저장
5. Slack 알림 (`ml_alert_to_slack.py`) – 악성 로그 탐지 시 알림 전송

6. 시스템 구성도
   <img width="336" height="350" alt="image" src="https://github.com/user-attachments/assets/d1a517d6-8a90-4b09-8a02-bfb53591301d" />


---

## 사용 방법

### 1. ML 추론 및 결과 저장
```bash
python main.py
---
### 2. Slack 알림 전송
python ml_alert_to_slack.py
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
