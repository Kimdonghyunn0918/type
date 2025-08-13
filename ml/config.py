# Elasticsearch 연결 설정
ES_HOST = "http://localhost:9200"  # 서버의 Elasticsearch 주소로 변경
ES_USER = "elastic"
ES_PASSWORD = "changeme"  #.env 파일과 동일한 비밀번호로 변경

# 분석할 데이터가 있는 인덱스 패턴
SOURCE_INDEX_PATTERN = "filebeat-suricata-*"

# 분석 결과를 저장할 인덱스 이름
DESTINATION_INDEX = "suricata-anomalies"
