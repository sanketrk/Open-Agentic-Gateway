FROM python:3.12-slim
WORKDIR /tests
COPY apps/control-plane/requirements.txt /tests/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY tests/streaming /tests
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 1001
ENTRYPOINT ["python"]
