# OpenAPI specs

Machine-readable (OpenAPI 3.1) descriptions of the two token-gated admin surfaces.
Use them to generate clients/CLIs, render browsable docs, or validate requests.

| Spec | Surface | Port | Bearer token |
|---|---|---|---|
| [`authz-admin.yaml`](authz-admin.yaml) | identity plane — roles, entitlements, suspension, customer API keys | `9300` | `IDENTITY_ADMIN_TOKEN` |
| [`control-plane.yaml`](control-plane.yaml) | routing plane — accounts, workspaces, members, auth-routes, domains | `9400` | `CONTROL_AUTH_TOKEN` |

These are **descriptive artifacts of the live routes**, not the source of truth — the
handlers in `identity-rs/authz-admin/src/` and `routing-rs/control-plane/src/` are. The
prose companion, with per-endpoint curl examples, is [`../admin-apis.md`](../admin-apis.md).

Both files carry a `servers:` block (local lab + in-cluster) and a `bearerAuth`
security scheme — set the base URL and token for your environment when you use them.

---

## Browse the docs

Render either spec as an interactive API reference.

```sh
# Redocly (live preview at http://localhost:8080)
npx @redocly/cli preview-docs docs/openapi/control-plane.yaml

# …or emit a single self-contained HTML file
npx @redocly/cli build-docs docs/openapi/control-plane.yaml -o control-plane.html

# …or Swagger UI via Docker (http://localhost:8080)
docker run --rm -p 8080:8080 \
  -e SWAGGER_JSON=/spec/control-plane.yaml \
  -v "$PWD/docs/openapi:/spec" swaggerapi/swagger-ui
```

## Generate a client or CLI

```sh
# List the available generators (languages/frameworks)
npx @openapitools/openapi-generator-cli list

# Generate, e.g., a Python client for the control-plane
npx @openapitools/openapi-generator-cli generate \
  -i docs/openapi/control-plane.yaml -g python -o clients/control-plane-python

# …or a TypeScript client via Docker
docker run --rm -v "$PWD:/local" openapitools/openapi-generator-cli generate \
  -i /local/docs/openapi/authz-admin.yaml -g typescript-axios -o /local/clients/authz-admin-ts
```

Common generator ids: `python`, `typescript-axios`, `go`, `rust`, `bash` (a CLI),
`html2` (static docs). Generated clients take the base URL + bearer token as config.

## Validate (after editing a spec)

```sh
# Strict OpenAPI 3.1 validation
python -m pip install openapi-spec-validator   # once
python -m openapi_spec_validator docs/openapi/control-plane.yaml

# …or with Redocly's linter
npx @redocly/cli lint docs/openapi/control-plane.yaml
```

## Keeping them honest

There is no CI drift-check wired, so if you change a handler's request/response shape,
update the matching spec (and `../admin-apis.md`) in the same change. To make drift a
build failure later, add a job that runs the validation above and, optionally,
`schemathesis run --checks all docs/openapi/control-plane.yaml --base-url …` against the
e2e stack.
