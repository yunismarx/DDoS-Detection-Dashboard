# Real-time DDoS Detection System (Cascading Hybrid Model)

This project is a comprehensive system for detecting Distributed Denial of Service (DDoS) attacks using a sequential hybrid approach (Cascading) that combines traditional rules (Signature-based) with Artificial Intelligence techniques (XGBoost & Deep Learning).

##  Project Structure

   `models/`: Contains trained models (`ddos_xgboost.pkl`, `scaler.pkl`, `dnn_classifier.keras`).
   `service/`: Fast API detection service (`detector_service.py`).
   `dashboard/`: Streamlit dashboard (`dashboard.py`) for visualization.
   `alerting/`: Alert system configuration and manager (`alert_manager.py` & `alert_config.json`).
   `traning_models.ipynb`: Jupyter notebook for data processing, model training, and saving.
   `test/`: Testing scripts (`be.py` for simulating benign and malicious traffic).

---

##  Usage Guide (Step-by-Step)

### 1. Prerequisites
Ensure all required libraries are installed:
```bash
pip install -r requirements.txt
```
*(Key dependencies: `fastapi`, `uvicorn`, `streamlit`, `pandas`, `numpy`, `scikit-learn`, `xgboost`, `tensorflow`, `joblib`, `requests`)*

---

### 2. Model Training
You must train and save the models before running the service.
1.  Open `traning_models.ipynb` in Jupyter Notebook or VS Code.
2.  Run all cells.
3.  Ensure the final cell successfully saves the following files to the `models/` directory:
    *   `scaler.pkl`
    *   `ddos_xgboost.pkl`
    *   `dnn_classifier.keras`

---

### 3. Start Detection Service
This service is the "brain" of the system.
Open a terminal and run:

```bash
python service/detector_service.py
```
> The service will run on port `8000` (http://localhost:8000).
> Interactive API documentation is available at: http://localhost:8000/docs

---

### 4. Start Dashboard
To visualize attacks and statistics.
Open a **new** terminal and run:

```bash
streamlit run dashboard/streamlit/dashboard.py
```
> The dashboard will automatically open in your browser (usually http://localhost:8501).

---

### 5. Test the System (Simulate Attacks)
To send simulated benign and malicious traffic to the service:
Open a **third** terminal and run:

```bash
cd test
python be.py
```
> The script will start sending various requests (HTTPS, Bruteforce, DDoS) and print the detection results.

---

##  Alerts Configuration
You can enable alerts (Telegram, Email) by modifying:
`alerting/alert_config.json`
*   Set `enabled: true` for desired channels.
*   Add your API Tokens/Credentials.

---

