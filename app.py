import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import pefile
import os
import streamlit as st

def extract_static_features(filepath):
    try:
        pe = pefile.PE(filepath)
        features = {
            "SizeOfOptionalHeader": pe.FILE_HEADER.SizeOfOptionalHeader,
            "Machine": pe.FILE_HEADER.Machine,
            "NumberOfSections": pe.FILE_HEADER.NumberOfSections,
            "TimeDateStamp": pe.FILE_HEADER.TimeDateStamp,
            "PointerToSymbolTable": pe.FILE_HEADER.PointerToSymbolTable,
            "Characteristics": pe.FILE_HEADER.Characteristics,
            "MajorLinkerVersion": pe.OPTIONAL_HEADER.MajorLinkerVersion,
            "MinorLinkerVersion": pe.OPTIONAL_HEADER.MinorLinkerVersion,
            "SizeOfCode": pe.OPTIONAL_HEADER.SizeOfCode,
            "AddressOfEntryPoint": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            "Subsystem": pe.OPTIONAL_HEADER.Subsystem
        }
        return pd.DataFrame([features])
    except Exception as e:
        print("Error extracting features:", e)
        return pd.DataFrame()

# Sample Dataset Creation
sample_data = {
    "SizeOfOptionalHeader": [224, 240],
    "Machine": [332, 34404],
    "NumberOfSections": [3, 5],
    "TimeDateStamp": [1234567890, 987654321],
    "PointerToSymbolTable": [0, 0],
    "Characteristics": [258, 130],
    "MajorLinkerVersion": [9, 14],
    "MinorLinkerVersion": [0, 0],
    "SizeOfCode": [1024, 2048],
    "AddressOfEntryPoint": [4096, 8192],
    "Subsystem": [2, 3],
    "label": ["Trojan", "Worm"]
}
df = pd.DataFrame(sample_data)
df.to_csv("malware_static_features.csv", index=False)

# Load and train model
data = pd.read_csv("malware_static_features.csv")
X = data.drop("label", axis=1)
y = data["label"]
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)
joblib.dump(clf, "malware_classifier.pkl")

# Streamlit UI
st.title("Malware Family Predictor - Static Analysis")
st.write("Upload a Windows executable (.exe) file to predict its malware family")
uploaded_file = st.file_uploader("Choose an .exe file", type=["exe"])

if uploaded_file:
    file_path = os.path.join("temp_uploaded.exe")
    with open(file_path, "wb") as f:
        f.write(uploaded_file.read())

    features = extract_static_features(file_path)
    if not features.empty:
        clf_loaded = joblib.load("malware_classifier.pkl")
        prediction = clf_loaded.predict(features)
        st.success(f"Predicted Malware Family: {prediction[0]}")
    else:
        st.error("Failed to extract features. Make sure the file is a valid Windows executable.")
