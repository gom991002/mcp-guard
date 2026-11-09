from __future__ import annotations

import argparse
import ipaddress
import os
import socket
import subprocess
import sys
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import gateway_mvp
import rule_sets
from gateway_mvp.live_catalog import LiveToolCatalog
from injection_throttle import RequestRateThrottle, ThrottlePolicy
from mcp_guard.admission import ServerIdentity, Stage0Admission
from mcp_guard.audit import (
    AuditRecorder, JsonlAuditSink, RecentEventsSink, TeeAuditSink, audit_event, decision_model,
    local_user, read_audit_log,
)
from mcp_guard.models import Verdict
from mcp_guard.registry import GuardRegistry
from mcp_guard.taint import SessionTaintStore
from server_registry.loader import load_gateway_config

from .adapter import HttpGatewayAdapter
from .correlation import CorrelationRunner
from .models import HttpRequest
from .state_storage import check_legacy_state, default_state_dir, verify_state_dir
from . import unbound_sessions


def build_server(
    address: tuple[str, int],
    adapter: HttpGatewayAdapter,
) -> ThreadingHTTPServer:
    class GuardHandler(BaseHTTPRequestHandler):
        def do_OPTIONS(self) -> None:
            self._handle()

        def do_POST(self) -> None:
            self._handle()

        def do_GET(self) -> None:
            self._handle()

        def do_DELETE(self) -> None:
            self._handle()

        def _handle(self) -> None:
            length = int(self.headers.get("Content-Length", "0") or "0")
            body = self.rfile.read(length) if length else b""
            request = HttpRequest(
                method=self.command,
                path=self.path,
                headers={key: value for key, value in self.headers.items()},
                body=body,
                client_ip=self.client_address[0],
            )
            response = adapter.handle(request)
            self.send_response(response.status_code)
            for key, value in response.headers.items():
                self.send_header(key, value)
            self.end_headers()
            if response.body:
                self.wfile.write(response.body)

        def log_message(self, format: str, *args: object) -> None:
            return

    return ThreadingHTTPServer(address, GuardHandler)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the mcp-guard MVP HTTP gateway.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--server", choices=("dev", "asgi"), default="dev",
                        help="dev: standard-library threads; asgi: uvicorn for production")
    parser.add_argument("--asgi-keep-alive", type=int, default=5,
                        help="Seconds an idle keep-alive connection stays open (asgi)")
    parser.add_argument("--asgi-limit-concurrency", type=int, default=0,
                        help="Answer 503 beyond this many concurrent requests (asgi, 0 = no limit)")
    parser.add_argument("--policy", default="configs/example-policy.json")
    parser.add_argument(
        "--servers",
        default="mvp/03-server-registration-config/configs/servers.json",
    )
    parser.add_argument("--state-dir",
                        help="private state folder; default is the current user's app state directory")
    parser.add_argument(
        "--approvals", default=None,
        help="Persistent stage 0 server identity approvals",
    )
    parser.add_argument(
        "--approve-server", metavar="NAME",
        help="Explicitly approve a changed server from the reviewed config and exit",
    )
    parser.add_argument(
        "--enroll", action="store_true",
        help="Allow first-use enrollment of configured upstreams in this run",
    )
    parser.add_argument(
        "--live-tools", action="store_true",
        help="Fetch, inspect, and cache actual upstream tools/list results",
    )
    parser.add_argument("--b-classifier", action="store_true",
                        default=os.environ.get("MCP_GUARD_B_CLASSIFIER") == "1",
                        help="Enable optional Horizon Labs B signals on descriptions and tool results")
    # 0.86: chosen on the development half of MCPTox so that word rules, structural signals
    # and the classifier together hold at most 2% of benign descriptions (held-out half:
    # 95.7% caught, 1.2% held; Korean set v2: 2.7% held). The model card's default is 0.5.
    parser.add_argument("--b-threshold", type=float,
                        default=float(os.environ.get("MCP_GUARD_B_THRESHOLD", "0.86")),
                        help="B signal review threshold, from 0 to 1 (default 0.86, measured)")
    parser.add_argument("--allow-user-reapproval", action="store_true",
                        help="let signed-in users accept low-risk tool definition changes for themselves "
                             "(D6-45; needs --auth oauth and --live-tools)")
    parser.add_argument("--allow-taint-exceptions", action="store_true",
                        help="Let signed-in users name exceptions to the tainted-session send block, "
                             "among tools the administrator allows, and approve each call on /approve "
                             "(D6-49; needs --auth oauth and --live-tools)")
    parser.add_argument("--description-llm-url",
                        help="OpenAI-compatible endpoint for the B description LLM check (D6-44)")
    parser.add_argument("--description-llm-model", help="model name for --description-llm-url")
    parser.add_argument("--description-llm-floor", type=float,
                        help="with --b-classifier: descriptions scoring below this skip the LLM check")
    parser.add_argument("--description-llm-http-host", action="append", default=[],
                        help="host allowed over plain http besides loopback (e.g. a private Docker name)")
    parser.add_argument("--audit-log", help="Append M1 audit events here (JSON Lines)")
    parser.add_argument("--audit-cloudwatch-group",
                        help="Also send audit events to this CloudWatch Logs group (needs --audit-log "
                             "as the local copy and --aws-region)")
    parser.add_argument("--audit-cloudwatch-stream", default=socket.gethostname(),
                        help="Log stream name (default: host name)")
    parser.add_argument("--audit-cloudwatch-endpoint",
                        help="CloudWatch Logs endpoint URL, e.g. a VPC endpoint")
    parser.add_argument("--audit-retention-days", type=int, default=180,
                        help="Keep rotated monthly copies of --audit-log this long (D6-24)")
    parser.add_argument("--correlation-interval", type=float, default=300,
                        help="Run the M1 correlation rules every N seconds (0 disables)")
    parser.add_argument("--correlation-lookback", type=float, default=24 * 3600,
                        help="Events the correlation rules look back over, in seconds")
    cloud = parser.add_argument_group("cloud entry (MVP 9: C2 OAuth, C3 credentials)")
    cloud.add_argument("--auth", choices=("none", "oauth"), default="none",
                       help="Require OAuth bearer tokens on /mcp")
    cloud.add_argument("--public-url", help="Public HTTPS origin, e.g. https://mcp.example.com")
    cloud.add_argument("--users", default="/config/users.json", help="Users allowed to sign in")
    cloud.add_argument("--oauth-clients",
                       help="Pre-registered OAuth clients with secrets, e.g. Gemini Enterprise")
    cloud.add_argument("--oauth-state")
    cloud.add_argument("--signing-key")
    cloud.add_argument("--redirect-uri", action="append", default=[],
                       help="Extra allowed OAuth redirect URI (repeatable)")
    cloud.add_argument("--trusted-proxy", action="append", default=[],
                       help="CIDR of a reverse proxy whose X-Forwarded-For is trusted")
    cloud.add_argument("--upstream-credentials",
                       help="JSON file mapping servers to secret references (C3)")
    cloud.add_argument("--upstream-tokens",
                       help="Per-user upstream OAuth tokens (servers with mode per_user)")
    cloud.add_argument("--upstream-token-store", choices=("file", "aws-secrets-manager"),
                       default="file", help="Where per-user upstream tokens are kept")
    cloud.add_argument("--aws-region",
                       default=os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION"),
                       help="AWS Region for --upstream-token-store aws-secrets-manager")
    cloud.add_argument("--aws-secret-prefix", default="mcp-guard/upstream",
                       help="Name prefix of the per-user token secrets")
    cloud.add_argument("--aws-kms-key-id", default="",
                       help="KMS key for new secrets (default: aws/secretsmanager)")
    cloud.add_argument("--shared-egress", action="append", default=[],
                       help="CIDR shared by many users (e.g. 160.79.104.0/21); IP-only limits skip it "
                            "for signed-in /mcp requests")
    cloud.add_argument("--shared-egress-feed", action="append", default=[], choices=("chatgpt",),
                       help="Fetch a client's published egress ranges at start and daily and treat them "
                            "like --shared-egress; the last good list is kept if a fetch fails")
    cloud.add_argument("--state-backend", choices=("file", "dynamodb"), default="file",
                       help="Where session taint and new-session counters live: the private state folder "
                            "(one gateway) or a DynamoDB table shared by several gateways")
    cloud.add_argument("--dynamodb-table", default=os.environ.get("MCP_GUARD_DYNAMODB_TABLE", ""),
                       help="DynamoDB table (partition key pk, string) for --state-backend dynamodb")
    cloud.add_argument("--dynamodb-endpoint", help="DynamoDB endpoint override (tests, local DynamoDB)")
    cloud.add_argument("--allow-unauthenticated", action="store_true",
                       help="Permit --auth none on a non-loopback address (testing only)")
    cloud.add_argument("--accept-unbound-sessions", action="store_true",
                       help="Relay tool calls without --auth oauth even though sessions then come "
                            "from a client header (M4 taint can be left by a new session id); "
                            "without it the gateway asks in a window or the terminal")
    args = parser.parse_args(argv)
    if not 0 <= args.b_threshold <= 1:
        parser.error("--b-threshold must be between 0 and 1")
    if (args.auth == "none" and not _is_loopback(args.host)
            and not args.allow_unauthenticated):
        parser.error("refusing to serve /mcp without auth on a non-loopback address; "
                     "use --auth oauth (or --allow-unauthenticated for testing)")
    if args.auth == "oauth" and not args.public_url:
        parser.error("--auth oauth requires --public-url")
    if args.upstream_token_store == "aws-secrets-manager" and not args.aws_region:
        parser.error("--upstream-token-store aws-secrets-manager needs --aws-region or AWS_REGION")
    if args.state_backend == "dynamodb" and not (args.dynamodb_table and args.aws_region):
        parser.error("--state-backend dynamodb needs --dynamodb-table and --aws-region")
    if args.audit_cloudwatch_group and not (args.audit_log and args.aws_region):
        parser.error("--audit-cloudwatch-group needs --audit-log (local copy) and --aws-region")

    root = Path.cwd()
    try:
        state_home = root / args.state_dir if args.state_dir else default_state_dir()
        intended = state_home.resolve(strict=False)
        for option in (args.approvals, args.oauth_state, args.signing_key, args.upstream_tokens):
            if option and not (root / option).resolve(strict=False).is_relative_to(intended):
                parser.error(f"old state path {root / option} is outside the private state folder; "
                             f"stop the gateway and run python -m http_gateway.state_storage "
                             f"{intended} --migrate-from {(root / option).parent}")
        check_legacy_state(root / ".mcp-guard", state_home)
        state_home = verify_state_dir(state_home)
    except RuntimeError as error:
        parser.error(str(error))
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.error(f"private state folder check failed: {error}; run "
                     f"python -m http_gateway.state_storage {state_home}")

    def state_file(override: str | None, name: str) -> Path:
        chosen = root / override if override else state_home / name
        if not chosen.resolve().is_relative_to(state_home):
            parser.error(f"{name} must be inside the private state folder")
        return chosen

    approvals_path = state_file(args.approvals, "stage0-approvals.json")
    oauth_state_path = state_file(args.oauth_state, "oauth-state.json")
    signing_key_path = state_file(args.signing_key, "signing.key")
    upstream_tokens_path = state_file(args.upstream_tokens, "upstream-tokens.json")
    if args.audit_log and not (root / args.audit_log).resolve().is_relative_to(state_home):
        parser.error("--audit-log must be inside the private state folder")
    policy = GuardRegistry.from_path(root / args.policy)
    config = load_gateway_config(root / args.servers, policy)
    model = decision_model(
        files={"policy": root / args.policy, "servers": root / args.servers},
        sources={"gateway": Path(gateway_mvp.__file__).parent,
                 "rules": Path(rule_sets.__file__).parent},
    )
    classifier = None
    if args.b_classifier:
        # Native inference libraries may terminate Python before an exception
        # can be handled. Probe in a child process so the gateway reports it.
        try:
            probe = subprocess.run([sys.executable, "-c", "import onnxruntime"],
                                   capture_output=True, timeout=15, check=False)
        except subprocess.TimeoutExpired:
            parser.error("B classifier runtime import timed out")
        if probe.returncode:
            parser.error("B classifier runtime could not load; check the ONNX Runtime installation")
        try:
            from b_classifier.prompt_guard import PromptGuardClassifier
            classifier = PromptGuardClassifier()
        except (ImportError, OSError, RuntimeError, ValueError) as error:
            parser.error(f"B classifier could not start: {error}")
        model["b_classifier"] = {"id": classifier.model_id,
                                 "revision": classifier.revision,
                                 "threshold": args.b_threshold}
    reapproval = None
    if args.live_tools:  # D6-45: changed definitions wait here for re-approval
        from gateway_mvp.reapproval_store import ReapprovalStore

        if args.allow_user_reapproval and args.auth != "oauth":
            parser.error("--allow-user-reapproval needs --auth oauth")
        reapproval = ReapprovalStore(state_home, allow_user=args.allow_user_reapproval)
    elif args.allow_user_reapproval:
        parser.error("--allow-user-reapproval needs --live-tools")
    exceptions = None
    if args.allow_taint_exceptions or policy.m4_value_policy is not None:
        if args.auth != "oauth" or not args.live_tools:
            parser.error("--allow-taint-exceptions needs --auth oauth and --live-tools"
                         if args.allow_taint_exceptions else
                         "M4 value approval needs --auth oauth and --live-tools")
        from gateway_mvp.taint_exceptions import TaintExceptionStore

        exceptions = TaintExceptionStore(state_home)
    description_reviewer = None
    if args.description_llm_url:
        if not args.description_llm_model:
            parser.error("--description-llm-url needs --description-llm-model")
        if args.description_llm_floor is not None and not args.b_classifier:
            parser.error("--description-llm-floor needs --b-classifier")
        from b_classifier.description_llm_client import OpenAICompatibleReviewer
        try:
            description_reviewer = OpenAICompatibleReviewer(
                args.description_llm_url, args.description_llm_model,
                http_hosts=tuple(args.description_llm_http_host),
                classifier_floor=args.description_llm_floor)
        except ValueError as error:
            parser.error(str(error))
        model["description_llm"] = {"id": description_reviewer.model_id,
                                    "classifier_floor": args.description_llm_floor}
    audit, recent = _audit_recorder(args, root, model)
    if not approvals_path.exists() and not args.enroll and not args.approve_server:
        parser.error("approval file is missing; use --enroll for first-time setup")

    def record_approval(identity: ServerIdentity, method: str) -> None:
        audit.record(audit_event(
            "server_approved", verdict="allow", server_name=identity.name,
            namespace=identity.namespace, user=local_user(),
            details={"method": method, "transport": identity.transport, "url": identity.url,
                     "source": identity.source}))

    admission = Stage0Admission(approvals_path, enroll=args.enroll,
                                on_enroll=lambda identity: record_approval(identity, "enroll"))
    if args.approve_server:
        upstream = next((s for s in config.upstreams if s.name == args.approve_server), None)
        if upstream is None:
            parser.error("server must be enabled and registered in --servers")
        identity = ServerIdentity(
            upstream.name, upstream.namespace, upstream.transport, upstream.url, upstream.source,
        )
        decision = admission.approve(identity, policy)
        if decision.verdict != Verdict.ALLOW:
            parser.error(decision.findings[0].message)
        record_approval(identity, "approve-server")
        audit.close()
        print(f"Stage 0 approved {upstream.name} from the configured server registry")
        return 0
    live_catalog = None
    list_client = None
    tool_call_client = None
    auth = None
    header_provider = None
    token_store = None
    per_user_names: frozenset[str] = frozenset()
    if args.auth == "oauth" or args.upstream_credentials:
        # Cloud entry is optional so the static demos need no MVP 9 path.
        from cloud_entry import (
            AuthorizationServer, OAuthSettings, OAuthStateStore, UpstreamCredentials,
            UserDirectory, load_or_create_key,
        )
        from cloud_entry.oauth import load_static_clients
        from cloud_entry.upstream_credentials import resolve_secret
        from cloud_entry.upstream_oauth import (
            SecretManagerTokenStore, UpstreamOAuth, UpstreamTokenStore,
        )

        if args.upstream_token_store == "aws-secrets-manager":
            from cloud_entry.aws_secrets import AwsSecretsManagerStore, default_credentials

            token_store = SecretManagerTokenStore(
                AwsSecretsManagerStore(args.aws_region, default_credentials(),
                                       kms_key_id=args.aws_kms_key_id),
                prefix=args.aws_secret_prefix,
            )
        else:
            token_store = UpstreamTokenStore(upstream_tokens_path)
        upstream_oauth = None
        if args.upstream_credentials:
            credentials = UpstreamCredentials.from_path(root / args.upstream_credentials)
            header_provider = credentials.headers_for
            per_user_names = credentials.per_user_names()
            if per_user_names:
                if args.auth != "oauth":
                    parser.error("per_user upstream credentials need --auth oauth")
                upstream_oauth = UpstreamOAuth(
                    args.public_url, credentials.per_user_servers(config.upstreams),
                    token_store, resolve_secret, audit=audit,
                )
                credentials.attach(upstream_oauth)
        if args.auth == "oauth":
            users = UserDirectory.from_path(root / args.users)
            auth = AuthorizationServer(
                OAuthSettings(issuer=args.public_url,
                              extra_redirect_uris=frozenset(args.redirect_uri)),
                users,
                load_or_create_key(signing_key_path),
                OAuthStateStore(oauth_state_path),
                upstream=upstream_oauth,
                audit=audit,
                static_clients=(load_static_clients(root / args.oauth_clients)
                                if args.oauth_clients else None),
            )
    if args.live_tools:
        # Static MVP demos remain independent of the relay packages.
        from tools_call_relay.client import HttpJsonRpcToolCallClient
        from tools_list_relay.client import HttpToolsListClient

        list_client = HttpToolsListClient(header_provider=header_provider)
        catalog_client = list_client
        if per_user_names:
            from cloud_entry.upstream_credentials import PerUserListClient

            catalog_client = PerUserListClient(list_client, per_user_names)
        live_catalog = LiveToolCatalog(catalog_client)
        tool_call_client = HttpJsonRpcToolCallClient(header_provider=header_provider)
    unbound = ""
    if tool_call_client is not None and args.auth != "oauth":
        # M4 taint follows the client's session header here: refuse unless accepted.
        unbound = unbound_sessions.confirm(args.accept_unbound_sessions)
        if not unbound:
            audit.close()
            parser.error(unbound_sessions.REFUSED)
        audit.record(audit_event(
            "startup_override", user=local_user(),
            details={"override": "unbound_sessions", "accepted_by": unbound, "host": args.host,
                     "port": args.port}))
    review_page = None
    if args.allow_user_reapproval:  # D6-45: --auth oauth is required above, so users exist
        from .review_page import ReviewPage

        review_page = ReviewPage(reapproval, users.verify, per_user_servers=per_user_names, audit=audit)
    approval_page = epochs = taint = None
    shared = None
    if args.state_backend == "dynamodb":  # several gateways behind a load balancer share these
        from cloud_entry.aws_secrets import default_credentials
        from cloud_entry.dynamo_state import DynamoSessionEpochs, DynamoTable, DynamoTaintStore

        shared = DynamoTable(args.dynamodb_table, args.aws_region, default_credentials(),
                             endpoint=args.dynamodb_endpoint)
    if tool_call_client is not None:
        taint = DynamoTaintStore(shared) if shared else SessionTaintStore(state_home / "sessions")
    if args.auth == "oauth" and tool_call_client is not None:
        # Signed-in users can start a new session after taint (Claude sends no conversation id).
        from .session_epochs import SessionEpochs

        epochs = DynamoSessionEpochs(shared) if shared else SessionEpochs(state_home)
    if exceptions is not None or epochs is not None:
        from .approval_page import ApprovalPage

        approval_page = ApprovalPage(exceptions, users.verify, audit=audit, epochs=epochs)
    throttle = RequestRateThrottle(ThrottlePolicy(shared_networks=tuple(args.shared_egress)))
    adapter = HttpGatewayAdapter(
        config,
        admission=admission,
        live_catalog=live_catalog,
        tool_call_client=tool_call_client,
        throttle=throttle,
        sleep_on_delay=True,
        auth=auth,
        trusted_proxies=tuple(args.trusted_proxy),
        audit=audit,
        classifier=classifier,
        b_threshold=args.b_threshold,
        description_reviewer=description_reviewer,
        reapproval=reapproval,
        review_url=f"{args.public_url.rstrip('/')}/review" if args.allow_user_reapproval and args.public_url else "",
        review_page=review_page,
        # M4: session taint in the private state folder, or shared in DynamoDB; it survives restarts
        taint=taint,
        exceptions=exceptions,
        approval_url=f"{args.public_url.rstrip('/')}/approve" if exceptions is not None else "",
        approval_page=approval_page,
        session_epochs=epochs,
        new_session_url=f"{args.public_url.rstrip('/')}/approve" if epochs is not None else "",
    )
    stop_watchers = threading.Event()
    if list_client is not None:
        for upstream in config.upstreams:
            identity = ServerIdentity(
                upstream.name, upstream.namespace, upstream.transport,
                upstream.url, upstream.source,
            )
            if admission.check(identity, policy).verdict != Verdict.ALLOW:
                continue
            threading.Thread(
                target=list_client.run_change_watcher,
                args=(upstream, adapter.tools_list_changed, stop_watchers, adapter.tools_list_watch_gap),
                daemon=True,
                name=f"mcp-guard-list-watch-{upstream.name}",
            ).start()
    if args.shared_egress_feed:
        from cloud_entry.egress_feeds import EgressFeed, SharedEgress

        shared = SharedEgress(throttle.set_fetched_shared_networks)
        for name in dict.fromkeys(args.shared_egress_feed):
            feed = EgressFeed(name, state_home, shared.apply, audit=audit)
            threading.Thread(target=feed.run_forever, args=(stop_watchers,), daemon=True,
                             name=f"mcp-guard-egress-{name}").start()
    if recent is not None:
        runner = CorrelationRunner(recent, audit, interval=args.correlation_interval,
                                   lookback=args.correlation_lookback)
        threading.Thread(target=runner.run_forever, args=(stop_watchers,), daemon=True,
                         name="mcp-guard-correlation").start()
    public = f"{args.public_url.rstrip('/')}/mcp" if args.public_url else f"http://{args.host}:{args.port}/mcp"

    def shutdown() -> None:
        stop_watchers.set()
        if token_store is not None:
            token_store.flush()  # values held back by the secret manager write interval
        audit.close()  # send audit events still queued for CloudWatch Logs

    print(f"mcp-guard HTTP gateway ({args.server}) listening on {args.host}:{args.port} "
          f"(MCP URL {public}, auth {args.auth}{', sessions unbound' if unbound else ''})")
    if args.server == "asgi":
        _serve_asgi(args, adapter, shutdown)
        return 0
    server = build_server((args.host, args.port), adapter)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        shutdown()
    return 0


def _serve_asgi(args: argparse.Namespace, adapter: HttpGatewayAdapter,
                shutdown: Callable[[], None]) -> None:
    """Production server: uvicorn running the standard-library ASGI app."""
    import uvicorn  # the only third-party package, needed only for --server asgi

    from .asgi import GatewayAsgiApp

    uvicorn.run(
        GatewayAsgiApp(adapter, on_shutdown=shutdown),
        host=args.host, port=args.port,
        proxy_headers=False,  # the adapter alone decides which proxies to trust
        server_header=False, lifespan="on", log_level="warning",
        timeout_keep_alive=args.asgi_keep_alive,
        limit_concurrency=args.asgi_limit_concurrency or None,
    )


def _audit_recorder(args: argparse.Namespace, root: Path,
                    model: dict) -> tuple[AuditRecorder, RecentEventsSink | None]:
    """Local JSON Lines copy, CloudWatch Logs as the main remote store (D6-22), and
    the in-memory window the correlation rules read (D6-25)."""
    if not args.audit_log:
        return AuditRecorder(), None
    local = root / args.audit_log
    sinks: list = [JsonlAuditSink(local, retention_days=args.audit_retention_days)]
    if args.audit_cloudwatch_group:
        # Cloud entry is optional so the static demos need no MVP 9 path.
        from cloud_entry.aws_logs import CloudWatchLogsSink
        from cloud_entry.aws_secrets import default_credentials

        sinks.append(CloudWatchLogsSink(
            args.aws_region, args.audit_cloudwatch_group, args.audit_cloudwatch_stream,
            default_credentials(), endpoint=args.audit_cloudwatch_endpoint))
    recent = None
    if args.correlation_interval > 0:
        recent = RecentEventsSink(args.correlation_lookback)
        since = datetime.now(UTC) - timedelta(seconds=args.correlation_lookback)
        recent.load(read_audit_log(local, include_rotated=True, since=since))
        sinks.append(recent)
    sink = sinks[0] if len(sinks) == 1 else TeeAuditSink(*sinks)
    return AuditRecorder(sink, path="remote", decision_model=model), recent


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


if __name__ == "__main__":
    raise SystemExit(main())

