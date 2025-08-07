*Malware Classification Using Static Analysis*

This project uses machine learning to classify Windows executables into malware families based on static features extracted from PE files.

 1.Features
- Extracts static features from `.exe` files using `pefile`
- Trains a Random Forest model on a synthetic dataset
- Includes a web interface built with Streamlit
- Predicts malware family from uploaded `.exe` file

 2.How to Run

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Launch the web app
```bash
streamlit run app.py
```

### 3. Upload a `.exe` file and get malware family prediction.

3. Files Included
- `app.py`: Main script with ML training and Streamlit app
- `malware_static_features.csv`: Sample dataset
- `malware_classifier.pkl`: Trained model
- `sample_exe/`: (Optional) Sample test files

4. Requirements
- Python 3.7+
- `streamlit`, `pefile`, `pandas`, `scikit-learn`, `joblib`

5. Future Scope
- Combine with dynamic analysis
- Use deep learning models
- Deploy as cloud API
