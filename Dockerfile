# SecretSentinel container image.
# Usage: docker run --rm -v "$PWD:/repo" secretsentinel:0.1.0.dev0 scan /repo
FROM python:3.12-slim AS build

WORKDIR /src
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir build \
 && python -m build --wheel --outdir /dist

FROM python:3.12-slim

# GitPython shells out to the git binary for history and staged scans.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git \
 && rm -rf /var/lib/apt/lists/*

# Install as root, then run as an unprivileged user.
COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -f /tmp/*.whl

RUN useradd --create-home --uid 10001 scanner
USER scanner

WORKDIR /repo
# Git refuses to read repositories owned by other users; trust the mounted repo.
RUN git config --global --add safe.directory '*'

ENTRYPOINT ["secretsentinel"]
CMD ["scan", "."]
