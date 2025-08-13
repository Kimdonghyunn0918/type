from sklearn.ensemble import IsolationForest
import pandas as pd

def preprocess_data(df):
    """모델 훈련을 위해 데이터를 전처리합니다."""
    # 예시: 숫자형 특성만 선택
    # 실제로는 IP 주소 변환, 범주형 데이터 인코딩 등 더 복잡한 전처리가 필요합니다.
    features = ['source.bytes', 'destination.bytes', 'network.bytes']
    
    # 특성이 데이터프레임에 있는지 확인하고 없으면 0으로 채웁니다.
    for feature in features:
        if feature not in df.columns:
            df[feature] = 0
            
    df_numeric = df[features].fillna(0)
    print(f"Preprocessing complete. Using features: {features}")
    return df_numeric

def train_and_predict(df_processed):
    """Isolation Forest 모델을 훈련하고 이상 징후를 예측합니다."""
    print("Training Isolation Forest model...")
    model = IsolationForest(contamination='auto', random_state=42)
    model.fit(df_processed)
    
    print("Predicting anomalies...")
    predictions = model.predict(df_processed)
    
    # -1 (이상) / 1 (정상)
    return predictions
