# ThreatLens — Windows Setup & Execution Guide

This document provides a step-by-step guide to installing, configuring, and running **ThreatLens** on **Windows 10 / Windows 11**.

---

## 1. System Requirements & Python Version

### Required Python Version
* **Recommended:** **Python 3.12** (any subversion: `3.12.0` – `3.12.8`, 64-bit)
* **Supported:** Python 3.11 or Python 3.12

> [!WARNING]
> **Do not use Python 3.13+ or Python 3.9 or older.**
> Core machine learning libraries (`scikit-learn`, `numpy`, `scipy`) require pre-compiled C/C++ binary wheels for Windows. Python 3.12 has official pre-built wheels for all dependencies in `requirements.txt`.

### Recommended Tools for Windows
* **Python 3.12 (64-bit)**: [Download from python.org](https://www.python.org/downloads/release/python-3128/)
  * **CRITICAL**: During installation, check the box **"Add python.exe to PATH"**.
* **Git for Windows**: [Download from git-scm.com](https://gitforwindows.org/)
* **Terminal**: Windows Terminal with PowerShell 7 or Windows PowerShell (built-in).
* *(Optional)* **Docker Desktop for Windows**: [Download from docker.com](https://www.docker.com/products/docker-desktop/) (requires WSL 2 backend).

---

## 2. Verify Your Windows Environment

Open **PowerShell** or **Command Prompt (CMD)** and check your versions:

```powershell
python --version
# Expected output: Python 3.12.x

git --version
# Expected output: git version 2.x.x
```

> [!TIP]
> If `python` opens the Microsoft Store, disable the Windows app execution aliases:
> * Go to **Windows Settings** → **Apps** → **Advanced app settings** → **App execution aliases**.
> * Turn **OFF** both "App Installer" toggles for `python.exe` and `python3.exe`.

---

## 3. Method A: Local Native Setup (Recommended for Development)

### Step 1: Clone or Open the Project

```powershell
# In PowerShell:
cd C:\Users\<YourUsername>\Downloads
git clone https://github.com/Aniket0025/ThreatLens.git
cd ThreatLens
```

---

### Step 2: Create a Virtual Environment

Isolate the project packages from system Python:

```powershell
python -m venv venv
```

---

### Step 3: Activate the Virtual Environment

#### In PowerShell:
If you receive the error `running scripts is disabled on this system`, allow script execution for the current session:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\venv\Scripts\Activate.ps1
```

#### In Command Prompt (cmd.exe):
```cmd
venv\Scripts\activate.bat
```

*(Your terminal prompt will now show `(venv)` at the beginning).*

---

### Step 4: Upgrade Pip & Install Dependencies

Ensure `pip` is updated, then install the pinned project requirements:

```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Verify that the machine learning packages loaded cleanly:

```powershell
python -c "import sklearn, pandas, joblib; print('Dependencies successfully loaded!')"
```

---

### Step 5: Configure Environment Variables

Create your local `.env` configuration file from the template:

```powershell
# In PowerShell:
Copy-Item .env.example .env

# Or in CMD:
copy .env.example .env
```

Open `.env` in Notepad or VS Code and verify:
```env
FLASK_DEBUG=false
SECRET_KEY=threatlens-local-secret-key-change-in-prod
MODEL_PATH=url_model.pkl
DATASET_PATH=../dataset/phishing_urls.csv
METRICS_PATH=model_metrics.json
ALLOWED_ORIGINS=*
PORT=5000
LOG_LEVEL=INFO
```

---

### Step 6: Start the Application

Start the Flask backend and ML inference engine:

```powershell
cd backend
python app.py
```

You will see output similar to:
```text
2026-11-01 [INFO] urlshield — Model loaded from url_model.pkl — 28 features
 * Serving Flask app 'app'
 * Running on http://127.0.0.1:5000
 * Running on http://<your-lan-ip>:5000
```

---

### Step 7: Open the Application in Your Browser

Open your browser and navigate to:
* **Web UI & Scanner**: [http://localhost:5000](http://localhost:5000)
* **Health Check**: [http://localhost:5000/health](http://localhost:5000/health)
* **Model Metrics**: [http://localhost:5000/api/v1/metrics](http://localhost:5000/api/v1/metrics)

---

## 4. Method B: Running with Docker Desktop on Windows

If you prefer containerized deployment with Nginx and Gunicorn:

### Prerequisites:
1. Install **Docker Desktop for Windows**.
2. Make sure the **WSL 2 based engine** is enabled in Docker Desktop settings.
3. Start Docker Desktop.

### Commands:

In PowerShell, from the project root (`ThreatLens` directory):

```powershell
# Build and start both containers
docker compose up -d --build

# Check running status
docker compose ps

# View backend logs
docker compose logs -f backend
```

### URLs when running via Docker:
* **Nginx Frontend & Proxy**: [http://localhost:3000](http://localhost:3000)
* **Backend API directly**: [http://localhost:8000](http://localhost:8000)
* **Health Check**: [http://localhost:8000/health](http://localhost:8000/health)

To stop the containers:
```powershell
docker compose down
```

---

## 5. Retraining the ML Model on Windows

If you want to train the model from the dataset on Windows:

```powershell
# From the project root, ensure venv is active:
cd backend
python train_model.py
```

This will:
1. Extract features from the dataset.
2. Train the 300-estimator `RandomForestClassifier`.
3. Compute Accuracy, Precision, Recall, F1, and 5-fold cross-validation.
4. Export updated `url_model.pkl` and `model_metrics.json`.

---

## 6. Windows Troubleshooting & FAQ

### Issue 1: `Activate.ps1 cannot be loaded because running scripts is disabled on this system`
* **Cause**: Windows PowerShell security policy blocks `.ps1` script execution by default.
* **Fix**: Run this command once in PowerShell:
  ```powershell
  Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
  ```
  Or for the current window only:
  ```powershell
  Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
  ```

---

### Issue 2: `error: Microsoft Visual C++ 14.0 or greater is required`
* **Cause**: Using an incompatible Python version (such as Python 3.13 or 32-bit Python) where wheels must compile from source.
* **Fix**: Uninstall Python and install **Python 3.12 (64-bit)** from [python.org](https://www.python.org/downloads/release/python-3128/). Pre-compiled wheels will be downloaded automatically without needing a C++ compiler.

---

### Issue 3: Port `5000` or `3000` is already in use
* **Cause**: Another service or container is using the port.
* **Fix**: Change the port in `.env` (e.g. `PORT=5050`) or in PowerShell find what is using the port:
  ```powershell
  netstat -ano | findstr :5000
  ```
  Kill the process by PID:
  ```powershell
  taskkill /PID <PID> /F
  ```

---

### Issue 4: `Model file not found: url_model.pkl`
* **Cause**: Running `python app.py` from the root directory instead of inside `backend/`.
* **Fix**: The code supports both, but running from `backend/` ensures all relative paths match:
  ```powershell
  cd backend
  python app.py
  ```

---

## 7. Quick Reference Cheatsheet

```powershell
# 1. Clone & enter
git clone https://github.com/Aniket0025/ThreatLens.git
cd ThreatLens

# 2. Virtual environment setup
python -m venv venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\venv\Scripts\Activate.ps1

# 3. Dependencies & config
pip install -r requirements.txt
Copy-Item .env.example .env

# 4. Run application
cd backend
python app.py

# 5. Access
# Open http://localhost:5000 in your browser
```
