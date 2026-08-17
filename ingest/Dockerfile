# Built from the REPO ROOT as context, because the schema lives outside this
# directory and Docker cannot COPY from above the build context.
#   docker compose build   (context: .., dockerfile: ingest/Dockerfile)
#
# Pinned like every other image in this estate, and for the same reason: a
# floating base means two runs of the same commit can behave differently.
FROM python:3.13-slim-bookworm

WORKDIR /app
COPY ingest/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ingest/ /app/ingest/
COPY schema/ /app/schema/
COPY rules/ /app/rules/

WORKDIR /app/ingest
ENTRYPOINT ["python", "cli.py"]
