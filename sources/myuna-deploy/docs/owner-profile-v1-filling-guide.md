# Owner Profile v1 filling guide

This template is for the Owner to fill personally. Do not generate the first real profile
from chat history, model guesses, third-party information, messages, media, database rows,
or provider responses.

1. Copy `templates/owner-profile-v1.blank.toml` into an Owner-controlled private working
   location. Do not edit the repository copy with real content.
2. Remove `template_only`, set `profile_revision` to a positive integer, and fill each body.
   Delete unused blank sections rather than inventing content.
3. Use only stable information:
   - `self_introduction`: how you choose to describe yourself.
   - `long_term_preference`: durable preferences and interaction style.
   - `long_term_goal`: goals expected to remain relevant beyond a few days.
   - `ongoing_project`: durable project identity/purpose, not current task status.
4. Keep each `section_id` and `topic_key` unique and stable. Use short keywords that you
   would naturally use when asking about that section.
5. Exclude current status, deadlines, next actions, temporary plans, recent events,
   observed time, expiry, private third-party facts, credentials, secrets, raw messages,
   media, and model text. Days-scale information belongs to P08 Active Temporal Context.
6. Review the complete file yourself. A controlled future intake will compute the exact
   SHA-256 and content-free receipt; approve that exact digest before installation.

The future private release is mode `0700` with `profile.toml` and `receipt.json` at `0600`.
The files are plaintext; no encryption claim is made. P07-A does not deploy the template or
enable live retrieval.
