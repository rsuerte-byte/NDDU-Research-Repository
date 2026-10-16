# Authentication setup

The repository accepts verified Google accounts at `@nddu.edu.ph`. A non-institutional account is accepted only when its exact email address is explicitly approved by the repository administrator. Finding `nddu` anywhere in an email address is not proof of affiliation and never grants access.

Configure the server with:

- `GOOGLE_CLIENT_ID`: the Google OAuth web client ID used by the login page.
- `NDDU_SESSION_SECRET`: a random secret of at least 32 bytes, used to sign eight-hour session cookies. Generate one with `python3 -c 'import secrets; print(secrets.token_urlsafe(48))'` and keep it private.
- `APPROVED_EXTERNAL_EMAILS`: optional comma-separated exact email addresses approved by the repository administrator.
- `NDDU_COOKIE_SECURE`: set to `true` when serving over HTTPS; leave unset for local HTTP development.

For example, set these environment variables in the deployment configuration and start the Node server with `npm start`. The Python server reads the same variables when started with `python3 server.py`. Never put the session secret in browser code or commit it to the repository. External users should ask the repository administrator to approve the Google account they intend to use.
