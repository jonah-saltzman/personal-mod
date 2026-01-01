# Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install deps
RUN pip install --no-cache-dir praw==7.8.1

# Copy script into image (rename if your file is different)
COPY reddit_comment_autodelete.py /app/reddit_comment_autodelete.py

# Unbuffered logs
ENV PYTHONUNBUFFERED=1

CMD ["python", "-u", "/app/reddit_comment_autodelete.py"]
