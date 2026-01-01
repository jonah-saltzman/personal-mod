# docker-compose.yml
services:
  reddit-autodeleter:
    build: .
    container_name: reddit-autodeleter
    restart: unless-stopped

    # IMPORTANT:
    # The OAuth callback is http://192.168.0.49:8090/callback
    # That address must be reachable *from your browser* and must hit this container.
    # Easiest is host networking on Linux.
    network_mode: "host"

    environment:
      # Fill these in (or put them in a .env file next to this compose file)
      CLIENT_ID: "${CLIENT_ID}"
      CLIENT_SECRET: "${CLIENT_SECRET}"
      USERNAME: "${USERNAME}"
      USER_AGENT: "${USER_AGENT:-comment-autodeleter/1.0 by ${USERNAME}}"

      # If you already generated one, set it here to skip browser OAuth next runs
      REFRESH_TOKEN: "${REFRESH_TOKEN:-}"

      # Must match your Reddit app redirect URI exactly:
      REDIRECT_HOST: "192.168.0.49"
      REDIRECT_PORT: "8090"
      REDIRECT_PATH: "/callback"

      POLL_SECONDS: "5"
      DELETE_IF_YOUNGER_THAN_SECONDS: "60"
      FETCH_LIMIT: "25"

      SEEN_TTL_SECONDS: "600"

      ALLOWED_SUBREDDITS: "${ALLOWED_SUBREDDITS:-}"
