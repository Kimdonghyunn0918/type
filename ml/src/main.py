from ml.src import data_loader, model
from ml import config

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Suricata → ML 예측 → AbuseIPDB 조회 → Elasticsearch 인덱싱 파이프라인
"""

from __future__ import annotations
import os, time, logging, threading, queue, signal, requests, joblib, warnings
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Tuple
from elasticsearch import Elasticsearch, helpers, ElasticsearchWarning  # type: ignore
import pandas as pd

warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=ElasticsearchWarning)

# ────────────────────────── 기본 설정 ──────────────────────────
ES_HOST        = os.getenv("ES_HOST", "http://localhost:9200")
SOURCE_INDEX   = os.getenv("SOURCE_INDEX", "suricata-*")
FETCH_SIZE     = 500
POLL_INTERVAL  = 5
NUM_WORKERS    = 8
PROCESS_BATCH  = 100
BULK_THRESHOLD = 100
BULK_FLUSH_SEC = 3

UTC, KST = timezone.utc, timezone(timedelta(hours=9))

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s %(levelname)s %(threadName)s ▶ %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S")
logger = logging.getLogger("hybrid_pipeline")
logging.getLogger("elasticsearch").setLevel(logging.WARNING)

es      = Elasticsearch([ES_HOST])
bundle  = joblib.load("../score_based.pkl")      # ← 모델 폴더
models  = bundle["models"]
feature_orders = bundle["feature_orders"]
attack_types   = bundle["attack_types"]
threshold      = bundle.get("threshold", 0.8)

payload_q: queue.Queue[tuple] = queue.Queue(FETCH_SIZE * 4)
bulk_q:    queue.Queue[dict]  = queue.Queue()

def get_target_index() -> str:
    return f"ml-classified-{datetime.now(KST).strftime('%Y.%m.%d')}"

# ── ML 예측 ────────────────────────────────────────────────────────
def predict_score_batch(payloads: List[str]) -> List[Tuple[int, str, float, list]]:
    from feature_engineering import apply_feature_engineering
    from feature_weight_map   import feature_weight_map

    df_full = apply_feature_engineering(
        pd.DataFrame({"payload": payloads}),
        attack_type=None, feature_weights=None)

    probs_per_attack: Dict[str, pd.Series] = {}
    for atk in attack_types:
        df = df_full.reindex(columns=feature_orders[atk], fill_value=0.0)
        for feat, w in feature_weight_map.get(atk, {}).items():
            if feat in df.columns:
                df[feat] *= w
        probs_per_attack[atk] = pd.Series(models[atk].predict_proba(df)[:, 1])

    results = []
    for i in range(len(payloads)):
        scores = [(atk, float(probs_per_attack[atk][i])) for atk in attack_types]
        scores.sort(key=lambda x: -x[1])
        best_atk, best_score = scores[0]
        label = int(best_score >= threshold)
        results.append((label, best_atk if label else "Normal", best_score, scores[:3]))
    return results

# ── AbuseIPDB 설정 ────────────────────────────────────────────────
_abuse_sess = requests.Session()
_abuse_sess.headers.update({
    "Accept": "application/json",
    "Key": os.getenv("ABUSEIPDB_KEY", "AbuseIPDB키 입력")
})

def query_abuseip(ip: str) -> Dict:
    try:
        r = _abuse_sess.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": "30"},
            timeout=5)
        r.raise_for_status()
        d = r.json()["data"]
        score   = d.get("abuseConfidenceScore")
        verdict = "malicious" if score is not None and score >= 30 else "benign"
        return {
            "ti_verdict"     : verdict,
            "ti_score"       : score,
            "abuse_total"    : d.get("totalReports"),
            "abuse_country"  : d.get("countryCode"),
            "abuse_last_seen": d.get("lastReportedAt")
        }
    except Exception as e:
        logger.warning("AbuseIPDB 실패: %s (%s)", ip, e)
        return {"ti_verdict":"unknown","ti_score":None,
                "abuse_total":None,"abuse_country":None,"abuse_last_seen":None}

# ── Fetch 스레드 (search_after 유지) ───────────────────────────────
def fetch_loop(stop_ev: threading.Event):
    last_sort, last_time = None, datetime.now(UTC) - timedelta(seconds=120)
    while not stop_ev.is_set():
        t0, now = time.time(), datetime.now(UTC)

        query = (
            {"query":{"bool":{"filter":[{"range":{"@timestamp":{"gte":last_time.isoformat(),
                                                               "lt":now.isoformat()}}}]}},
             "sort":[{"@timestamp":{"order":"asc"}},{"_id":{"order":"asc"}}],
             "size":FETCH_SIZE}
            if last_sort is None else
            {"search_after": last_sort,
             "sort":[{"@timestamp":{"order":"asc"}},{"_id":{"order":"asc"}}],
             "size":FETCH_SIZE}
        )

        try:
            hits = es.search(index=SOURCE_INDEX, body=query)["hits"]["hits"]
            for h in hits:
                payload_q.put((h["_id"], h["_source"],
                               h["_source"].get("payload_printable",""), now))
                last_sort = h["sort"]

            logger.info("📥 Fetch %d건, 큐=%d, %.3fs",
                        len(hits), payload_q.qsize(), time.time()-t0)

            if not hits:
                time.sleep(POLL_INTERVAL)
        except Exception as e:
            logger.exception("Fetch 오류: %s", e)
            time.sleep(POLL_INTERVAL)

# ── Worker 스레드 ────────────────────────────────────────────────
def process_worker(stop_ev: threading.Event):
    while not stop_ev.is_set():
        try:
            first = payload_q.get(timeout=0.5)
        except queue.Empty:
            continue
        if first is None:
            payload_q.task_done(); break

        batch = [first]
        for _ in range(PROCESS_BATCH - 1):
            try:
                itm = payload_q.get_nowait()
            except queue.Empty:
                break
            if itm is None:
                payload_q.task_done(); payload_q.put(None); break
            batch.append(itm)

        t0 = time.time()
        ips = [item[1].get("src_ip") for item in batch]

        t_ml_start = time.time()
        ml_results = predict_score_batch([p for *_ , p , _ in batch])
        t_ml_end   = time.time()

        abuse_map = {ip: query_abuseip(ip) for ip in {i for i in ips if i}}
        t_ab_end  = time.time()

        for (fid, src, _payload, now), (lbl, atk, sc, top3) in zip(batch, ml_results):
            ip = src.get("src_ip")
            ab = abuse_map.get(ip, {"ti_verdict":"unknown","ti_score":None,
                                    "abuse_total":None,"abuse_country":None,"abuse_last_seen":None})

            doc = src | {
                "ml_label"       : lbl,
                "ml_score"       : sc,
                "ml_attack_type" : atk,
                "ml_top_3"       : [{"attack":a,"score":float(s)} for a,s in top3],
                "ml_predicted_at": now.isoformat(),
                **ab
            }
            bulk_q.put({"_op_type":"update",
                        "_index"   : get_target_index(),
                        "_id"      : fid,
                        "doc"      : doc,
                        "doc_as_upsert": True})

        for _ in batch: payload_q.task_done()

        logger.info("⏱ Worker %d건  ML %.3fs  AbuseIPDB %.3fs  총 %.3fs",
                    len(batch),
                    t_ml_end - t_ml_start,
                    t_ab_end - t_ml_end,
                    t_ab_end - t0)

# ── Bulk 인덱서 ─────────────────────────────────────────────────
def bulk_indexer(stop_ev: threading.Event):
    buf, last_flush = [], time.time()
    while True:
        try:   act = bulk_q.get(timeout=0.5)
        except queue.Empty: act = None

        if act is None:
            if stop_ev.is_set() and not buf and bulk_q.empty(): break
        else:
            buf.append(act); bulk_q.task_done()

        flush = (len(buf) >= BULK_THRESHOLD or
                 (buf and time.time()-last_flush >= BULK_FLUSH_SEC) or
                 (act is None and (stop_ev.is_set() or bulk_q.empty())))
        if flush and buf:
            try:
                helpers.bulk(es, buf, raise_on_error=False)
                logger.info("💾 Bulk %d건 저장", len(buf))
            except Exception as e:
                logger.exception("Bulk 오류: %s", e)
            buf.clear(); last_flush = time.time()
    logger.info("Bulk 인덱서 종료")

# ── main ───────────────────────────────────────────────────────
def main():
    stop_ev = threading.Event()
    def _sig(*_): logger.info("종료 시그널"); stop_ev.set()
    signal.signal(signal.SIGINT, _sig); signal.signal(signal.SIGTERM, _sig)

    threads = [threading.Thread(target=bulk_indexer, args=(stop_ev,), name="Bulk", daemon=True)]
    threads += [threading.Thread(target=process_worker, args=(stop_ev,), name=f"Worker-{i+1}", daemon=True)
                for i in range(NUM_WORKERS)]
    threads += [threading.Thread(target=fetch_loop, args=(stop_ev,), name="Fetch", daemon=True)]

    for t in threads: t.start()

    try:
        while not stop_ev.is_set():
            time.sleep(0.3)
    finally:
        stop_ev.set()
        for _ in range(NUM_WORKERS): payload_q.put(None)
        bulk_q.put(None)
        payload_q.join(); bulk_q.join()
        for t in threads: t.join(timeout=3)
        logger.info("✅ 파이프라인 종료")

if __name__ == "__main__":
    main()

