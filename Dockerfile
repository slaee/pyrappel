FROM alpine:3.20 AS chroot

# Install necessary packages
RUN apk add --no-cache musl-dev libc-dev python3 curl ca-certificates linux-headers build-base cmake ninja python3-dev && \
    update-ca-certificates


# Install uv, then move the binary to a global PATH dir
RUN set -eux; \
    curl -LsSf https://astral.sh/uv/install.sh | sh; \
    # Move to /usr/local/bin regardless of where the script put it
    if [ -x /root/.local/bin/uv ]; then mv /root/.local/bin/uv /usr/local/bin/uv; fi; \
    if [ -x /root/.cargo/bin/uv ]; then mv /root/.cargo/bin/uv /usr/local/bin/uv; fi; \
    chmod +x /usr/local/bin/uv; \
    /usr/local/bin/uv --version

# (Optional) keep PATH clean; not required since uv is in /usr/local/bin
# ENV PATH="/usr/local/bin:${PATH}"

# Create user directory
RUN mkdir -p /home/user/

WORKDIR /home/user

COPY pyproject.toml .
COPY uv.lock .

# Create a uv venv and sync dependencies (no shell activation needed)
RUN uv venv && \
    source .venv/bin/activate && \
    uv sync

COPY pyrappel /home/user/pyrappel
COPY pyrappel.py .

RUN chmod +x pyrappel.py

FROM gcr.io/kctf-docker/challenge@sha256:d884e54146b71baf91603d5b73e563eaffc5a42d494b1e32341a5f76363060fb

# Copy chroot environment
COPY --from=chroot / /chroot

# Copy nsjail configuration
COPY nsjail.cfg /home/user/

EXPOSE 1337

# Set up the challenge service with proper privileges
CMD kctf_setup && \
    socat \
      TCP-LISTEN:1337,reuseaddr,fork \
      EXEC:"kctf_pow nsjail --config /home/user/nsjail.cfg --cwd /home/user -- ./pyrappel.py -a x64 -s 0x8000000000",pty,sane
