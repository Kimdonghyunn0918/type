feature_weight_map = {
    "Cross_Site_Scripting": {
        # 기존 대비 payload_length 중요도↑ (분포 차이 매우 큼)
        "payload_length": 1.4,
        "script_obfuscation_count": 1.3,    # 그대로 유지
        "html_tag_depth": 1.3,             # 그대로 유지
        "event_handler_count": 1.3,        # 그대로 유지
        "uri_depth": 1.3,                  # 그대로 유지
        "entropy_level": 1.2,              # 1.3 → 1.2 (차이 크나 다른 피처가 더 우선)
        "symbol_density": 1.1,             # 0.7 → 1.1 (분산 중간, XSS에서 특수문자 중요)
        "url_encoding_ratio": 1.1,         # 0.7 → 1.1 (XSS 페이로드 인코딩 차이)
        "repetition_ratio": 1.1,           # 1.3 → 1.1 (차이는 있으나 과도 가중치 방지)
        "numeric_token_ratio": 1.0,        # 그대로 유지 (1.0)
        "digit_ratio": 1.0                 # 그대로 유지 (1.0)
    },
    "Path_Disclosure": {
        "payload_length": 1.4,             # 1.3 → 1.4 (분포 차이 매우 큼)
        "uri_depth": 1.3,                  # 그대로 유지
        "basename_entropy": 1.3,           # 그대로 유지
        "path_depth": 1.3,                 # 그대로 유지
        "entropy_level": 1.2,              # 1.0 → 1.2 (정상 대비 차이 명확)
        "digit_ratio": 1.2,                # 1.3 → 1.2 (분포 차이 큼)
        "token_count": 1.0,                # 신규 추가 (정상 대비 +2.67)
        "url_encoding_ratio": 1.3,         # 그대로 유지
        "repetition_ratio": 1.3,           # 그대로 유지
        "symbol_density": 0.5,             # 그대로 유지 (0.5)
        "numeric_token_ratio": 1.0         # 그대로 유지 (1.0)
    },
    "HOST_Scan": {
        "port_like_token_count": 1.5,      # 1.3 → 1.5 (정상 대비 차이 매우 큼)
        "ip_like_pattern": 1.4,            # 1.3 → 1.4 (정상 대비 차이 큼)
        "scan_keyword_count": 1.3,         # 그대로 유지 (1.3)
        "payload_length": 1.3,             # 그대로 유지 (1.3)
        "digit_ratio": 1.1,                # 1.3 → 1.1 (차이 중간)
        "entropy_level": 1.0,              # 0.5 → 1.0 (차이 명확)
        "url_encoding_ratio": 0.5,         # 그대로 유지 (0.5)
        "numeric_token_ratio": 0.8,        # 그대로 유지 (0.8)
        "symbol_density": 0.7,             # 그대로 유지 (0.7)
        "repetition_ratio": 1.3,           # 그대로 유지 (1.3)
        "uri_depth": 1.0,                  # 1.3 → 1.0 (차이 크지 않음)
        "digit_ratio": 1.1                 # (중복 기재 제거)
    },
    "System_Cmd_Execution": {
        "payload_length": 1.4,             # 1.3 → 1.4 (정상 대비 차이 큼)
        "word_diversity_feature": 1.3,     # 그대로 유지 (1.3)
        "entropy_level": 1.2,              # 그대로 유지 (1.3 → 1.2)
        "uri_depth": 1.1,                  # 0.0 → 1.1 (정상 대비 차이 중간)
        "url_encoding_ratio": 1.1,         # 0.5 → 1.1 (차이 명확)
        "symbol_density": 0.8,             # 그대로 유지 (0.8)
        "repetition_ratio": 1.1,           # 1.3 → 1.1 (차이 중간)
        "numeric_token_ratio": 1.0,        # 그대로 유지 (1.0)
        "digit_ratio": 1.0                 # 그대로 유지 (1.0)
        # uri_depth: 0.0 → 1.1 으로 수정
    },
    "SQL_Injection": {
        "payload_length": 1.5,             # 1.3 → 1.5 (정상 대비 차이 매우 큼)
        "entropy_level": 1.3,              # 그대로 유지 (1.3)
        "url_encoding_ratio": 1.3,         # 0.7 → 1.3 (차이 큼)
        "sql_keyword_count": 1.3,          # 1.1 → 1.3 (공격특화 신호 강화)
        "uri_depth": 1.2,                  # 그대로 유지 (1.3 → 1.2)
        "repetition_ratio": 1.1,           # 1.3 → 1.1 (차이 중간)
        "digit_ratio": 1.0,                # 1.0 유지
        "numeric_token_ratio": 1.0,        # 그대로 유지 (1.0)
        "param_key_entropy": 1.0,          # 그대로 유지 (1.0)
        "param_value_entropy": 1.3,        # 그대로 유지 (1.3)
        "symbol_density": 0.7              # 그대로 유지 (0.7)
    },
    "Vulnerability_Scan": {
        "payload_length": 1.4,             # 1.3 → 1.4 (차이 큼)
        "uri_depth": 1.3,                  # 그대로 유지 (1.2 → 1.3)
        "digit_ratio": 1.2,                # 1.3 → 1.2 (차이 중간)
        "entropy_level": 1.2,              # 1.3 → 1.2 (차이 중간)
        "scan_keyword_count": 1.3,         # 그대로 유지 (1.3)
        "numeric_token_ratio": 0.7,        # 그대로 유지 (0.7)
        "symbol_density": 0.7,             # 그대로 유지 (0.7)
        "repetition_ratio": 1.3,           # 그대로 유지 (1.3)
        "url_encoding_ratio": 1.3          # 그대로 유지 (1.3)
    },
    "Leakage_Through_NW": {
        "token_count": 1.4,                # 신규 추가 (정상 대비 차이 큼)
        "payload_length": 1.3,             # 그대로 유지 (1.3)
        "error_code_count": 1.3,           # 그대로 유지 (1.3)
        "uri_depth": 1.2,                  # 그대로 유지 (1.3 → 1.2)
        "digit_ratio": 1.1,                # 1.3 → 1.1 (차이 중간)
        "entropy_level": 1.0,              # 그대로 유지 (1.0)
        "numeric_token_ratio": 1.0,        # 그대로 유지 (1.0)
        "symbol_density": 0.7,             # 그대로 유지 (0.7)
        "url_encoding_ratio": 0.7,         # 1.3 → 0.7 (차이 작음)
        "repetition_ratio": 0.0            # 그대로 유지 (0.0)
    },
    "Directory_Indexing": {
        "token_count": 1.4,                # 신규 추가 (정상 대비 차이 매우 큼)
        "uri_depth": 1.3,                  # 1.1 → 1.3 (차이 큼)
        "payload_length": 1.3,             # 1.3 유지
        "digit_ratio": 1.2,                # 1.3 → 1.2 (차이 중간)
        "entropy_level": 1.1,              # 0.7 → 1.1 (차이 명확)
        "path_depth": 1.3,                 # 그대로 유지 (1.3)
        "basename_entropy": 1.3,           # 그대로 유지 (1.3)
        "symbol_density": 0.8,             # 그대로 유지 (0.8)
        "numeric_token_ratio": 0.8,        # 그대로 유지 (0.8)
        "url_encoding_ratio": 1.3,         # 그대로 유지 (1.3)
        "repetition_ratio": 0.9            # 그대로 유지 (0.9)
    },
    "Automatically_Searching_Infor": {
        "payload_length": 1.3,             # 0.4 → 1.3 (정상 대비 차이 크므로 강화)
        "uri_depth": 1.2,                  # 그대로 유지 (1.3 → 1.2)
        "token_count": 1.2,                # 신규 추가 (정상 대비 차이 큼)
        "repetition_ratio": 1.1,           # 그대로 유지 (1.0 → 1.1)
        "entropy_level": 1.3,              # 그대로 유지 (1.3)
        "digit_ratio": 1.1,                # 1.0 → 1.1 (차이 중간)
        "url_encoding_ratio": 1.3,         # 그대로 유지 (1.3)
        "symbol_density": 0.7,             # 그대로 유지 (0.7)
        "numeric_token_ratio": 0.5,        # 그대로 유지 (0.5)
        "word_diversity": 1.3              # 그대로 유지 (1.3)
    }
}

