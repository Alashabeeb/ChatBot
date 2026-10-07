# Hotfix Deploy (superseded)

**Don't follow the old hotfix-only steps.** All work now lives on `main`, so pulling `main` brings the full set of changes: a database migration, a required `JWT_SECRET`, and new frontend packages. The old instructions said "no database changes" and would lead to a backend that refuses to start.

**Use `docs/DEPLOY.md` instead.** It includes the hotfix (fabricated tools unregistered, read-only audit) along with everything else.
