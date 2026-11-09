# Self-hosted deployment (Render, Railway, Fly.io, EC2, GCP Cloud Run, ...)
#   docker build -t intel-platform .
#   docker run -p 8501:8501 intel-platform
# Mount a full warehouse to serve the complete dataset instead of the demo snapshot:
#   docker run -p 8501:8501 -v "$PWD/warehouse:/app/warehouse" intel-platform
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PORT=8501
EXPOSE 8501
HEALTHCHECK CMD python -c "import urllib.request,os;urllib.request.urlopen(f'http://localhost:{os.environ.get(\"PORT\",8501)}/_stcore/health')"
CMD streamlit run app.py --server.port=${PORT} --server.address=0.0.0.0
