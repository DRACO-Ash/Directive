# syntax=docker/dockerfile:1
# Hardened, flattened Python container for the Bluestaq App Store container template.
# Adapted from .claude/skills/deploy-recipes/templates/python/Dockerfile.
#
# Three properties are load-bearing and each closes a real platform failure class:
#   * the package manager never reaches the shipped image, so the policy scan finds no
#     toolchain CVE;
#   * the setuid and setgid sweep is the LAST mutation in the prep stage, because user
#     creation can re-introduce the class the sweep just cleared;
#   * the shipped stage is FLATTENED, because the policy scan reads layer history and a
#     later chmod cannot remove a bit an earlier base layer physically carries.
#
# No ENV PORT and no ENV DATA_DIR. An ENV line always beats a code fallback chain, so a
# baked default would silently defeat the value the platform injects.

# ---- build: install the hash-locked requirements into an isolated virtual environment ----
FROM python:3.12-slim@sha256:2c941e860699f878900b0edc2403613c234d4b32eda3cc9fa7036991a2a63c4a AS build
ENV PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
COPY requirements.txt .
RUN pip install --require-hashes --no-deps -r requirements.txt

# ---- prep: assemble the runtime filesystem, then establish the invariants last ----
FROM python:3.12-slim@sha256:2c941e860699f878900b0edc2403613c234d4b32eda3cc9fa7036991a2a63c4a AS prep
# No `apt-get upgrade` here, deliberately. It installs whatever Debian ships at build
# time into a digest-pinned base, so the shipped image stops being reproducible from its
# pinned inputs and the change set is unreviewed. Patch by rebasing to a newer pinned
# digest instead, which is reviewable and reproducible.
# Remove the package manager and build toolchain. The scanner judges what ships, not
# what runs, and pip carries advisories the running service never needs.
# The base is Debian, so the OS package manager comes out too: leaving apt, apt-get and
# dpkg in the shipped image hands an attacker with code execution a working installer.
#
# The EXECUTABLES come out. The package database at /var/lib/dpkg deliberately STAYS.
# Deleting it removes no capability: glibc, openssl and the rest still ship. What it
# removes is the scanner's ability to enumerate them, so the platform policy scan and any
# software bill of materials would report zero operating-system packages and therefore
# zero operating-system vulnerabilities. That is a false clean scan in front of an
# assessor, which is worse than the finding it hides.
RUN rm -rf /usr/bin/apt /usr/bin/apt-get /usr/bin/apt-cache /usr/bin/apt-config \
           /usr/bin/apt-key /usr/bin/apt-mark /usr/bin/dpkg /usr/bin/dpkg-deb \
           /usr/bin/dpkg-divert /usr/bin/dpkg-query /usr/bin/dpkg-split \
           /usr/bin/dpkg-statoverride /usr/bin/dpkg-trigger /usr/sbin/dpkg-reconfigure \
           /usr/lib/apt /var/lib/apt/lists /etc/apt
RUN python -m pip uninstall -y pip setuptools wheel 2>/dev/null || true \
 && rm -rf /usr/local/lib/python3.12/ensurepip \
           /usr/local/lib/python3.12/site-packages/pip \
           /usr/local/lib/python3.12/site-packages/setuptools \
           /usr/local/lib/python3.12/site-packages/wheel \
           /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.12
COPY --from=build /opt/venv /opt/venv
# The virtual environment ships too, so its own copy of the package manager comes out
# as well. Leaving it would put pip back into the shipped image through the side door.
RUN rm -rf /opt/venv/lib/python3.12/site-packages/pip \
           /opt/venv/lib/python3.12/site-packages/pip-*.dist-info \
           /opt/venv/lib/python3.12/site-packages/setuptools \
           /opt/venv/lib/python3.12/site-packages/setuptools-*.dist-info \
           /opt/venv/lib/python3.12/site-packages/wheel \
           /opt/venv/lib/python3.12/site-packages/wheel-*.dist-info \
           /opt/venv/lib/python3.12/site-packages/pkg_resources \
           /opt/venv/bin/pip /opt/venv/bin/pip3 /opt/venv/bin/pip3.12 \
           /opt/venv/bin/wheel
WORKDIR /app
COPY wsgi.py ./
COPY src ./src
# Create the runtime user, then take ownership. Nothing that could set a setgid bit may
# run after the sweep below.
# The source tree stays root-owned and world-readable, so the runtime user cannot
# rewrite its own code: a write primitive then buys no persistence across a restart.
RUN useradd --uid 10001 --system --no-create-home --shell /usr/sbin/nologin appuser \
 && chmod -R a+rX /app
# THE LAST MUTATION IN THIS STAGE. Files and directories both: a file-only sweep misses
# the setgid directories the policy scan stops on. Fails closed.
RUN find / -xdev -perm /6000 \( -type f -o -type d \) -exec chmod a-s {} +
# The sweep above is a mutation, so it cannot fail. This is the assertion: the build stops
# here if any setuid or setgid bit survived it. A check rather than another mutation, so it
# does not reopen the ordering problem the sweep-last rule exists to close.
RUN [ -z "$(find / -xdev -perm /6000 \( -type f -o -type d \) -print -quit)" ]

# ---- ship: one clean layer, so the policy scan finds nothing in layer history ----
FROM scratch
COPY --from=prep / /
ENV PATH="/opt/venv/bin:/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin" \
    PYTHONPATH="/app/src" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
USER 10001:10001
EXPOSE 8080
# Readiness proves storage with a real write and races a hard timeout, so a stalled
# mount fails with a diagnosis instead of hanging until the platform kills the pod.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["python","-c","import os,urllib.request;urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('PORT','8080')+'/readyz',timeout=4).read()"]
# Bind 0.0.0.0 and read PORT, defaulting to 8080. Gunicorn defaults to 127.0.0.1, which
# the platform probe cannot reach, so this line is load-bearing. `exec` so SIGTERM
# reaches gunicorn and shutdown does not hang.
CMD ["sh","-c","exec gunicorn wsgi:app -b 0.0.0.0:${PORT:-8080} --workers 2 --threads 4 --timeout 60 --access-logfile - --error-logfile -"]
