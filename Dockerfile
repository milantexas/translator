FROM python:3.11-slim
ARG WITH_ARGOS=1
ENV PYTHONUNBUFFERED=1 XDG_DATA_HOME=/data
WORKDIR /app
COPY requirements.txt requirements-argos.txt ./
RUN pip install --no-cache-dir -r requirements.txt && \
    if [ "$WITH_ARGOS" = "1" ]; then pip install --no-cache-dir -r requirements-argos.txt; fi
COPY . .
EXPOSE 8000
CMD ["sh", "-c", "python setup_models.py && exec gunicorn -b 0.0.0.0:8000 -w 1 --threads 4 -t 180 app:app"]
