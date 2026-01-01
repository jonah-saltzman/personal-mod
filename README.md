# Reddit Comment Auto-Deleter

Automatically deletes **your own Reddit comments** shortly after you post them, with support for an allowlist of subreddits where comments are **never** deleted.

This is designed to help curb impulse arguing by removing comments within a configurable time window.

---

## Features

- Deletes **comments only** (never posts)
- Polls your account every few seconds
- Deletes comments newer than a configurable age (default: 60s)
- **Allowlisted subreddits** where comments are preserved
- Uses Reddit OAuth with a **local callback server**
- Docker + Docker Compose friendly
- Uses a persistent refresh token after first auth

---

## How It Works

1. Uses Reddit OAuth (via PRAW)
2. Runs a tiny HTTP server locally to receive the OAuth callback
3. Periodically fetches your newest comments
4. Deletes comments younger than `DELETE_IF_YOUNGER_THAN_SECONDS`
5. Skips deletion for allowlisted subreddits

---

## Requirements

- A Reddit account
- A Reddit **app** (script or web app)
- Docker + Docker Compose (recommended)

---

## Reddit App Setup

Create a Reddit app at:  
https://www.reddit.com/prefs/apps