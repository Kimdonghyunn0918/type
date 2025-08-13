import re
import math
import string
import base64
import pandas as pd
from collections import Counter

# ───────── 공통 피처 함수 ─────────
def payload_length(p):          
    return len(p)

def digit_ratio(p):             
    return sum(c.isdigit() for c in p) / (len(p) or 1)

def symbol_density(p):      
    # 기존에는 string.punctuation 전체를 봤으나, 여기서는 주요 특수문자 패턴을 사용
    return len(re.findall(r"[<>\'\";()|&~!@#$%^*]", p)) / max(len(p), 1)

def entropy_level(p):
    # 이제 실제 연속형 엔트로피 계산
    cnt = Counter(p)
    total = len(p)
    if total == 0:
        return 0.0
    probs = [v / total for v in cnt.values() if v > 0]
    return -sum(x * math.log2(x) for x in probs)

def repetition_ratio(p):
    # (전체 길이) / (유니크 문자 수) 형태로 변경
    return len(p) / len(set(p)) if len(set(p)) > 0 else 0

def uri_depth(p):               
    return p.count("/")

def url_encoding_ratio(p):      
    # 정확한 %XX 형태만 카운트
    return len(re.findall(r"%[0-9a-fA-F]{2}", p)) / max(len(p), 1)

def numeric_token_ratio(p):
    tokens = re.split(r"\W+", p)
    return len([t for t in tokens if t.isdigit()]) / (len(tokens) or 1)

def token_count(p):
    # 간단히 공백 기준 토큰 수로 대체하거나, 필요하면 정교하게 조정 가능
    # 여기서는 공백 기준 split
    return len(p.split())

# ───────── 공격별 피처 함수 ─────────
def script_obfuscation_count(p): 
    return len(re.findall(r"(eval\(|unescape\(|setTimeout\(|String\.fromCharCode)", p, flags=re.I))

def event_handler_count(p):     
    return len(re.findall(r"on[a-z]+\s*=", p, flags=re.I))

def html_tag_depth(p):          
    return p.count("<") - p.count("</")

def path_depth(p):              
    return p.count("/")

def basename_entropy(p):        
    # 경로 마지막 부분의 연속형 엔트로피
    base = p.strip("/").split("/")[-1]
    return entropy_level(base)

def error_pattern_match(p):     
    # "Fatal error", "Warning:" 등의 패턴
    return int(bool(re.search(r"(fopen|Fatal error|Warning:|in /var|include\()", p, flags=re.I)))

def ip_like_pattern(p):         
    return int(bool(re.search(r"(\d{1,3}\.){3}\d{1,3}", p)))

def port_like_token_count(p):   
    return len(re.findall(r":\d{2,5}(?!\d)", p))

def scan_keyword_count(p):      
    return len(re.findall(r"(open|filtered|nmap|masscan|nikto|sqlmap|hydra)", p, flags=re.I))

def error_code_count(p):        
    return len(re.findall(r"\b(4\d{2}|5\d{2})\b", p))

def sql_keyword_count(p):       
    return len(re.findall(r"\b(select|insert|update|delete|drop|union|from|where|having|and|or|not|null|sleep|benchmark|--|#)\b", p, flags=re.I))

def param_key_entropy(p):       
    return entropy_level("".join(re.findall(r"[?&]([^=]+)=", p)))

def param_value_entropy(p):     
    return entropy_level("".join(re.findall(r"[?&][^=]+=([^&]+)", p)))

def is_backup_file(p):          
    return int(bool(re.search(r"(\.bak$|\.old$|~$)", p)))

def word_diversity(p):          
    tokens = p.split()
    return len(set(tokens)) / len(tokens) if tokens else 0

# ───────────────────────────────
# 3. 공통 및 공격별 피처 리스트
# ───────────────────────────────
common_features = [
    "payload_length",
    "digit_ratio",
    "symbol_density",
    "entropy_level",
    "repetition_ratio",
    "uri_depth",
    "url_encoding_ratio",
    "numeric_token_ratio",
    "token_count"
]

attack_specific_features = {
    "Cross_Site_Scripting": [
        "script_obfuscation_count",
        "event_handler_count",
        "html_tag_depth",
        "symbol_density"
    ],
    "Path_Disclosure": [
        "path_depth",
        "basename_entropy",
        "error_pattern_match"
    ],
    "HOST_Scan": [
        "ip_like_pattern",
        "port_like_token_count",
        "scan_keyword_count"
    ],
    "System_Cmd_Execution": [
        "symbol_density",
        "payload_length",
        "word_diversity"
    ],
    "SQL_Injection": [
        "sql_keyword_count",
        "param_key_entropy",
        "param_value_entropy",
        "symbol_density"
    ],
    "Vulnerability_Scan": [
        "scan_keyword_count"
    ],
    "Leakage_Through_NW": [
        "error_code_count",
        "repetition_ratio",
        "path_depth"
    ],
    "Directory_Indexing": [
        "path_depth",
        "is_backup_file",
        "basename_entropy"
    ],
    "Automatically_Searching_Infor": [
        "word_diversity",
        "payload_length"
    ]
}

# ───────────────────────────────
# 4. 피처 함수 매핑
# ───────────────────────────────
feature_functions = {
    fn.__name__: fn
    for fn in [
        payload_length,
        digit_ratio,
        symbol_density,
        entropy_level,
        repetition_ratio,
        uri_depth,
        url_encoding_ratio,
        numeric_token_ratio,
        token_count,
        script_obfuscation_count,
        event_handler_count,
        html_tag_depth,
        path_depth,
        basename_entropy,
        error_pattern_match,
        ip_like_pattern,
        port_like_token_count,
        scan_keyword_count,
        error_code_count,
        sql_keyword_count,
        param_key_entropy,
        param_value_entropy,
        is_backup_file,
        word_diversity
    ]
}

# ───────────────────────────────
# 5. 최종 피처 엔지니어링 함수
# ───────────────────────────────
def apply_feature_engineering(
    df: pd.DataFrame,
    attack_type: str,
    feature_weights: dict | None = None
) -> pd.DataFrame:
    """
    payload 컬럼을 기반으로 공통 + 특화 피처를 생성합니다.
    feature_weights가 주어지면 가중치를 곱해 반영합니다.

    Args:
        df (pd.DataFrame): 'payload' 컬럼을 포함한 DataFrame
        attack_type (str): 카테고리 이름 (공격 유형)
        feature_weights (dict, optional): {feature_name: weight} 딕셔너리

    Returns:
        pd.DataFrame: 계산된 피처들만 모은 DataFrame
    """
    weights = feature_weights or {}
    # 지정된 공격 유형의 피처 목록; 없으면 모든 공격별 피처 사용
    atk_feats = attack_specific_features.get(
        attack_type,
        [f for feats in attack_specific_features.values() for f in feats]
    )

    # 공통 피처 + 공격별 피처 순서대로 컬럼 이름 모음
    cols, seen = [], set()
    for c in common_features + atk_feats:
        if c not in seen:
            cols.append(c)
            seen.add(c)

    # 각 피처 함수 적용
    for c in cols:
        df[c] = df["payload"].apply(feature_functions[c]) * weights.get(c, 1.0)

    # 결과로는 cols 순서에 맞춘 DataFrame 반환
    return df[cols].copy()

