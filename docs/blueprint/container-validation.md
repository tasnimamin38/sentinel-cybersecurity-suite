# Container validation

The CI workflow validates the Compose interpolation and builds both production container images from the repository root build context.

## CI checks

- docker compose config --quiet with non-production CI-only interpolation values
- docker build --pull -f backend/Dockerfile
- docker build --pull -f frontend/Dockerfile

The build job does not start the stack or exercise production traffic. Runtime health, persistent-volume behavior, read-only filesystem behavior, dropped capabilities, egress policy and database migration execution still require a controlled deployment test environment.

Do not use CI-only interpolation values as deployment credentials. Production must use independently generated secrets from a secret manager.
