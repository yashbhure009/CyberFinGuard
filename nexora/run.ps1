Set-Location app
python -m pip install -r requirements.txt
python -m uvicorn app:app --reload --port 8200
