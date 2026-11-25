FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOME=/data
WORKDIR /app
COPY hosted/requirements.txt /tmp/hosted-requirements.txt
RUN pip install --no-cache-dir -r /tmp/hosted-requirements.txt \
    && groupadd --gid 10001 klar && useradd --uid 10001 --gid klar --no-create-home klar \
    && install -d -m 0700 -o klar -g klar /data /run/klar
COPY app.py assistant.py core.py wirex.py import_template.csv LICENSE ./
COPY fonts/ fonts/
COPY static/ static/
COPY templates/ templates/
COPY hosted/ hosted/
USER 10001:10001
EXPOSE 8000
