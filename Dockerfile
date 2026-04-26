FROM python:3.12-slim@sha256:9e01bf1ae5db7649a236da7be1e94ffbbbdd7a93f867dd0d8d5720d9e1f89fab

WORKDIR /app

RUN addgroup --system --gid 1001 app && adduser --system --uid 1001 --ingroup app app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=app:app app/ ./app/
COPY --chown=app:app templates/ ./templates/
COPY --chown=app:app frontend/dist/ ./frontend/dist/
COPY --chown=app:app frontend/src/i18n/locales/ ./frontend/src/i18n/locales/

ENV PYTHONUNBUFFERED=1
EXPOSE 8000

USER app

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
