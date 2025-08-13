from elasticsearch import Elasticsearch
import pandas as pd
from ml import config

def get_es_client():
    """Elasticsearch 클라이언트 객체를 생성하고 반환합니다."""
    try:
        client = Elasticsearch(
            hosts=,
            basic_auth=(config.ES_USER, config.ES_PASSWORD)
        )
        if client.ping():
            print("Connected to Elasticsearch successfully.")
            return client
        else:
            print("Could not connect to Elasticsearch.")
            return None
    except Exception as e:
        print(f"Error connecting to Elasticsearch: {e}")
        return None

def fetch_data(client, index_pattern):
    """Elasticsearch에서 데이터를 가져와 Pandas DataFrame으로 변환합니다."""
    print(f"Fetching data from index pattern: {index_pattern}")
    # 실제 환경에서는 더 정교한 쿼리가 필요합니다 (예: 시간 범위, 필드 선택)
    query = {
        "query": {
            "match_all": {}
        }
    }
    
    try:
        response = client.search(
            index=index_pattern,
            body=query,
            size=10000  # 한 번에 가져올 문서 수
        )
        
        hits = [hit['_source'] for hit in response['hits']['hits']]
        df = pd.json_normalize(hits)
        print(f"Successfully fetched {len(df)} documents.")
        return df
    except Exception as e:
        print(f"Error fetching data: {e}")
        return pd.DataFrame()
