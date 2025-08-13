프로젝트 개요
본 프로젝트는 네트워크 트래픽을 실시간으로 탐지, 수집, 처리, 분석하고, 머신러닝을 통해 잠재적인 위협과 이상 징후를 식별하는 엔드투엔드 파이프라인을 구축하는 것을 목표로 합니다. 전체 시스템은 Docker 및 Docker Compose를 사용하여 모듈식으로 구성되어 있어 배포와 확장이 용이합니다.

주요 기능
실시간 위협 탐지: Suricata를 사용하여 네트워크 트래픽에서 알려진 위협, 악성 코드 및 비정상적인 활동을 탐지합니다.

중앙 집중식 로그 관리: Filebeat, Logstash, Elasticsearch를 사용하여 여러 소스로부터의 로그를 중앙에서 수집하고 저장합니다.

데이터 시각화 및 분석: Kibana를 사용하여 대화형 대시보드를 구축하고, 데이터를 시각적으로 탐색하며, 보안 이벤트를 심층 분석합니다.

머신러닝 기반 이상 탐지: 분리된 Python 모듈이 Elasticsearch의 데이터를 활용하여 비지도 학습 모델(예: Isolation Forest)을 통해 규칙 기반 시스템이 놓칠 수 있는 미묘한 이상 패턴을 식별합니다.

프로젝트 구조
프로젝트는 세 가지 주요 구성 요소로 나뉩니다.

server/: ELK 스택(Elasticsearch, Logstash, Kibana)을 포함하는 중앙 분석 및 시각화 서버입니다.

sensor/: 네트워크 트래픽을 모니터링하고 로그를 생성하는 Suricata 및 Filebeat 에이전트입니다.

ml/: Elasticsearch에 저장된 데이터를 사용하여 고급 분석 및 이상 탐지를 수행하는 독립적인 머신러닝 모듈입니다.

시작하기
사전 요구 사항
Docker

Docker Compose

설정 및 실행
**리포지토리 복제:**bash
git clone <repository-url>
cd network-security-platform


환경 변수 설정:
루트 디렉토리의 .env 파일을 프로젝트에 맞게 수정합니다. 이 파일은 Docker Compose 파일들에서 사용할 버전, 비밀번호, 포트 등의 변수를 정의합니다.

코드 스니펫

#.env

# ELK Stack 버전
ELASTIC_STACK_VERSION=8.19.1

# Elasticsearch 설정
ELASTIC_PASSWORD=changeme
ES_PORT=9200

# Kibana 설정
KIBANA_PORT=5601

# Logstash 설정
LOGSTASH_PORT=5044
서버 스택 실행:
server 디렉토리로 이동하여 Docker Compose를 사용하여 ELK 스택을 시작합니다.

Bash

cd server/
docker-compose up -d
센서 실행:
모니터링할 네트워크 세그먼트의 호스트에서 sensor 디렉토리로 이동하여 Suricata와 Filebeat를 시작합니다. sensor/docker-compose.yml 파일이 server의 Logstash에 연결되도록 네트워크 설정을 확인해야 합니다.

Bash

cd sensor/
docker-compose up -d
Kibana 접속:
웹 브라우저에서 http://localhost:5601로 접속하여 Kibana 대시보드에 접근합니다.

버전 관리 지침
안정적인 시스템 운영을 위해 구성 요소 간의 버전 호환성을 유지하는 것이 매우 중요합니다.

최신 버전을 사용해 볼 수 있지만, 만약 호환성 충돌이 발생할 경우 아래에 명시된 버전을 사용하시기 바랍니다.

구성 요소	권장 버전
Elasticsearch	8.19.1
Kibana	8.19.1
Logstash	8.19.1
Filebeat	8.19.1
Suricata	8.0.0
elasticsearch-py	8.14.0

#### `.env`
```dotenv
# ELK Stack 버전
# 모든 Elastic 구성 요소(Elasticsearch, Kibana, Logstash, Filebeat)는 이 버전을 사용합니다.
ELASTIC_STACK_VERSION=8.19.1

# Elasticsearch 설정
# Elasticsearch에 접근하기 위한 비밀번호입니다. 실제 환경에서는 더 강력한 비밀번호를 사용하세요.
ELASTIC_PASSWORD=changeme
ES_PORT=9200

# Kibana 설정
KIBANA_PORT=5601

# Logstash 설정
# Filebeat가 Logstash로 데이터를 보낼 때 사용하는 포트입니다.
LOGSTASH_PORT=5044
