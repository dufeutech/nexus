# http-request-timeouts

Add per-request HTTP timeouts to the axum servers (control-plane admin+ops, tenant-router, sidecar, sync-worker) to close the platform-wide Slowloris/slow-body DoS gap; adopt tower-http TimeoutLayer.
