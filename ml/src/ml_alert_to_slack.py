#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import textwrap
import time
from datetime import datetime, timedelta, timezone
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from elasticsearch import Elasticsearch

ES_HOST = "http://localhost:9200"
INDEX = "ml-*"
TIME_RANGE_MIN = 5
CACHE_FILE = "/tmp/slack_alert_cache.json"
LOG_FILE = "/var/log/ml_alert.log"

CHANNEL_ID = "클라이언트 ID입력"
SLACK_TOKEN = os.getenv("SLACK_TOKEN", "슬랙 토큰값 입력")

es = Elasticsearch(ES_HOST)
client = WebClient(token=SLACK_TOKEN)

def log(message):
    print(message)
    with open(LOG_FILE, "a") as f:
        f.write(f"{message}\n")

def load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r") as f:
            return set(json.load(f))
    return set()

def save_cache(cache):
    with open(CACHE_FILE, "w") as f:
        json.dump(list(cache), f)

def search_recent_alerts():
    now = datetime.now(timezone.utc)
    q = {
        "query": {
            "bool": {
                "must": [
                    {"term": {"event_type.keyword": "alert"}},
                    {"range": {"@timestamp": {
                        "gte": (now - timedelta(minutes=TIME_RANGE_MIN)).isoformat(),
                        "lte": now.isoformat()
                    }}}
                ]
            }
        },
        "_source": ["@timestamp", "alert.*", "http.*", "flow_id"],
        "size": 50,
        "sort": [{"@timestamp": "desc"}]
    }
    return es.search(index=INDEX, body=q)["hits"]["hits"]

def send_slack_alert(hit):
    src = hit["_source"]
    alert = src.get("alert", {})
    http = src.get("http", {})

    blocks = [{
        "type": "section",
        "text": {"type": "mrkdwn", "text": (
            f"*🚨 시그니처:* `{alert.get('signature','N/A')}`\n"
            f"*📅 시각:* `{src.get('@timestamp')}`\n"
            f"*📂 범주:* `{alert.get('category')}` | "
            f"*심각도:* `{alert.get('severity')}`\n"
            f"*🌐 Host:* `{http.get('hostname','-')}` | "
            f"*Method:* `{http.get('http_method','-')}`\n"
            f"*🧾 Flow ID:* `{src.get('flow_id','-')}`\n"
        )}
    }]

    try:
        resp = client.chat_postMessage(channel=CHANNEL_ID, text=":rotating_light: ML Alert!", blocks=blocks)
        thread_ts = resp["ts"]
    
        raw_json = json.dumps(src, ensure_ascii=False, indent=2, sort_keys=True)
        raw_json = textwrap.shorten(raw_json, width=3800, placeholder=" …(생략)…")
        client.chat_postMessage(channel=CHANNEL_ID, thread_ts=thread_ts, text=f"```json\n{raw_json}\n```")
        log(f"[+] Slack 알림 전송됨: {src.get('@timestamp')} | {alert.get('signature')}")
    except SlackApiError as e:
        log(f"Slack error: {e}")

def main_loop():
    cache = load_cache()
    while True:
        hits = search_recent_alerts()
        if hits:
            for h in hits:
                src = h["_source"]
                key = f"{src.get('@timestamp')}|{src.get('flow_id')}"
                if key in cache:
                    continue
                send_slack_alert(h)
                cache.add(key)
            save_cache(cache)
        else:
            log("🟢 새 alert가 없습니다.")
        time.sleep(2)

if __name__ == "__main__":
    main_loop()

