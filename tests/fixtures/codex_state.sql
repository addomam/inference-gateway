-- SPDX-License-Identifier: Apache-2.0
-- Adapted from OpenAI Codex. Copyright 2025 OpenAI.
-- Modified for infer: retain the threads table; omit upstream query indexes.
-- License and attribution: LICENSES/Apache-2.0.txt and THIRD_PARTY_NOTICES.md at the repository root.
-- Source: https://github.com/openai/codex/blob/8531184b49bcb160175a84e140b659a83a426df7/codex-rs/state/migrations/0001_threads.sql
CREATE TABLE threads (
    id TEXT PRIMARY KEY,
    rollout_path TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    source TEXT NOT NULL,
    model_provider TEXT NOT NULL,
    cwd TEXT NOT NULL,
    title TEXT NOT NULL,
    sandbox_policy TEXT NOT NULL,
    approval_mode TEXT NOT NULL,
    tokens_used INTEGER NOT NULL DEFAULT 0,
    has_user_event INTEGER NOT NULL DEFAULT 0,
    archived INTEGER NOT NULL DEFAULT 0,
    archived_at INTEGER,
    git_sha TEXT,
    git_branch TEXT,
    git_origin_url TEXT
);
