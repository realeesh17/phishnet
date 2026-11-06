# PhishNet

PhishNet is a Chrome Manifest V3 extension and Python API for explainable phishing-risk checks. The extension can analyze the active tab or a URL entered manually. The API supports local FastAPI development and the Azure Functions Python v2 programming model.

## What is included

- URL validation and features for length, HTTPS, IP-address hosts, subdomain count, suspicious terms, user information, and punycode.
- A transparent, rule-based baseline score. It is not a trained classifier and has not been evaluated against a labeled dataset.
- Optional OpenPhish feed and PhishTank API checks. Both are disabled unless configured; unavailable providers are reported in the response.
- A Chrome popup that displays the verdict, score, indicators, and feed status.
- Backend tests for valid and invalid URLs, risk scoring, and threat-feed matches.

Domain age is reported as unknown (`null`): this MVP does not perform WHOIS or DNS lookups. The app does not fetch or navigate to the submitted URL.

## Run the API locally

From the repository root, create a virtual environment and install the backend dependencies. To run the Azure Functions host, install Azure Functions Core Tools v4 first:

```powershell
python -m venv backend/.venv
.\backend\.venv\Scripts\python.exe -m pip install -r backend/requirements.txt
cd backend
func start
```

For local Functions Core Tools runs, copy `backend/local.settings.example.json` to `backend/local.settings.json` (ignored by Git) and start Azurite; the example keeps optional providers and telemetry disabled.

The plan routes are `http://localhost:7071/api/health` and `http://localhost:7071/api/analyze`; interactive API documentation is at `http://localhost:7071/docs`. For a dependency-light FastAPI development session, use `python -m uvicorn app.main:app --host 127.0.0.1 --port 7071` from `backend/`.

Alternatively, run the API and Azurite emulator with `docker compose up --build` from the repository root. The API binds locally by default. Keep it local unless you add authentication, HTTPS, and appropriate network controls before exposing it beyond your machine.

### Optional threat intelligence

- Set `OPENPHISH_ENABLED=true` to check the official OpenPhish text feed. The feed is cached in memory for five minutes.
- Set `PHISHTANK_API_KEY` to enable the PhishTank URL-check endpoint.

Provider checks use fixed provider endpoints, have short timeouts, and do not fetch the submitted site. Provider outages are returned as `unavailable`; they do not count as a clean result. Feed checks send the submitted URL to the configured provider, so review their privacy terms before enabling them.

## Build and load the Chrome extension

```powershell
cd extension
npm install
npm run build
```

In Chrome, open `chrome://extensions`, enable **Developer mode**, choose **Load unpacked**, and select `extension\dist`. Keep the API running on `localhost:7071`.

To use a different local API URL at build time:

```powershell
$env:VITE_PHISHNET_API_BASE_URL = "http://localhost:7071/api"
npm run build
```

The API CORS policy accepts the PhishNet Chrome extension origin and local Vite development origins. The extension manifest grants access only to local API hosts.

## Test

```powershell
cd backend
python -m pytest
```

The test suite mocks threat-intelligence providers and does not make external network requests.

## Compare ML models with your labeled dataset

No labeled dataset is included. To compare the requested classifiers, provide a local CSV with `url,label` columns; use `phishing`/`malicious`/`1` and `legitimate`/`benign`/`0` labels. Install scikit-learn and run the benchmark:

```powershell
cd backend
python -m pip install -r ml-requirements.txt
python -m scripts.benchmark_models C:\path\to\labeled_urls.csv --output model-comparison.json
```

The script reports accuracy, precision, recall, F1, ROC-AUC, and a confusion matrix for Logistic Regression, Decision Tree, Random Forest, and SVM. It also includes XGBoost if the optional `xgboost` package is installed. It uses a reproducible stratified holdout split; review duplicates and dataset quality before interpreting results. The live API continues to use the transparent baseline until a trained and validated model is deliberately integrated.

## API example

```powershell
Invoke-RestMethod -Method Post `
  -Uri http://localhost:7071/api/analyze `
  -ContentType "application/json" `
  -Body '{"url":"https://example.com"}'
```

The response includes the verdict, explainable indicators, source-check statuses, heuristic version, extracted features, and diagnostic score. `low_concern` means only that this heuristic found no strong signals; it is not a guarantee that a site is safe.

## Limitations and next steps

- The score is a baseline heuristic, not a trained or calibrated ML model.
- The model comparison script needs a labeled dataset; none was supplied, so this repository makes no performance claims and does not ship a trained model.
- Domain age and reputation signals need a privacy-reviewed data source and an explicit timeout/cache strategy.
- Do not use this MVP as the only protection against phishing.
