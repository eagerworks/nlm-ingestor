FROM 090802221799.dkr.ecr.us-west-2.amazonaws.com/chainguard/python:3.11.15-dev-060426

# Switch to root to install system packages
USER root

# Add the Wolfi OS community repository
RUN apk update && apk add --no-cache wget && \
    wget https://packages.wolfi.dev/os/wolfi-signing.rsa.pub -O /etc/apk/keys/wolfi-signing.rsa.pub && \
    echo "https://packages.wolfi.dev/os" >> /etc/apk/repositories && \
    apk update && apk add --no-cache \
    bash \
    openjdk-21-jre \
    tesseract \
    file \
    libmagic \
    libxml2 libxml2-dev \
    libxslt libxslt-dev \
    zlib zlib-dev \
    build-base \
    qpdf qpdf-dev \
    git \
    unzip \
    openssh \
    postgresql-client && \
    # Manually download Tesseract English data
    # Because language data packages are named differently or not available
    mkdir -p /usr/share/tessdata && \
    wget https://github.com/tesseract-ocr/tessdata/raw/main/eng.traineddata -O /usr/share/tessdata/eng.traineddata

# Create a non-root user
RUN addgroup -S appuser -g 1001 && \
    adduser -S -u 1001 -G appuser -h /home/appuser appuser

ENV APP_HOME=/home/appuser
ENV PYTHONPATH="${APP_HOME}"
ENV PYTHONUNBUFFERED=1
ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk
ENV PATH="${PATH}:${JAVA_HOME}/bin"

WORKDIR ${APP_HOME}

# Create necessary directories
RUN mkdir -p ${APP_HOME}/whl && chown -R appuser:appuser ${APP_HOME}

# Copy dependencies
COPY whl/*.whl ${APP_HOME}/whl/
COPY pyproject.toml poetry.lock ./

# Install Python dependencies
RUN pip install --upgrade pip && \
    pip install poetry && \
    poetry config virtualenvs.create false && \
    poetry install --no-root

# Copy application code
COPY . ./

# Set up SSH known_hosts
RUN mkdir -p ${APP_HOME}/.ssh && \
    chmod 700 ${APP_HOME}/.ssh && \
    (command -v ssh-keyscan >/dev/null 2>&1 && ssh-keyscan github.com >> ${APP_HOME}/.ssh/known_hosts || true) && \
    chmod 600 ${APP_HOME}/.ssh/known_hosts 2>/dev/null || true

# Download NLTK data
RUN python -m nltk.downloader -d /usr/share/nltk_data stopwords punkt punkt_tab && \
    python -c "import tiktoken; tiktoken.get_encoding('cl100k_base')"

# Fix ownership
RUN chown -R appuser:appuser ${APP_HOME}

# Switch to non-root user
USER 1001

# Ensure run.sh is executable
RUN chmod +x run.sh

EXPOSE 5001
# Override the base image's Python ENTRYPOINT with bash
ENTRYPOINT []
# Use bash explicitly
CMD ["/usr/bin/bash", "./run.sh"]
