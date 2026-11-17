FROM mcr.microsoft.com/playwright/python:v1.49.0-noble
WORKDIR /srv/gwreview
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && pip install --no-cache-dir "playwright==1.49.0"
COPY app ./app
RUN useradd -m gwr && mkdir /data && chown gwr /data
USER gwr
ENV GWR_DATA_DIR=/data GWR_HOST=0.0.0.0 GWR_PORT=8080
EXPOSE 8080
HEALTHCHECK CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/api/health')"
CMD ["python", "-m", "app"]
