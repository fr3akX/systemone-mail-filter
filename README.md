# systemone-mail-filter

A Go **after-queue Postfix filter** using TypeSafe Jev. Spam gets a configurable
Subject prefix (default `[SPAM]`); all messages continue through normal delivery.
Message category and independent abuse probabilities are available in headers
and JSON logs. There is no spam rejection, quarantine, or deletion.

```text
Internet → Postfix queue → systemone-mail-filter :10025 → Jev
                                ↓
                       Postfix :10026 → delivery
```

## Build and try it

Use a current Go release. `go.mod` selects Go 1.27.1 automatically when Go
toolchain downloads are enabled; the minimum language version is Go 1.26.

```sh
go build -o bin/systemone-mail-filter ./cmd/systemone-mail-filter
go test -race ./...
./bin/systemone-mail-filter -config config.example.json -check
```

Set `JEV_KEY` in the environment or a local `.env` file. `.env` is ignored by Git;
existing environment variables take precedence over dotenv values. The key is
never included in logs. Use `-env-file /path/to/file` to select another file or
`-env-file ''` to disable dotenv loading.

These examples send **synthetic messages** to the real Jev API, without SMTP
delivery. Classification mode returns JSON; filter mode writes a rewritten RFC
5322 message to stdout. Logs go to stderr. API use may incur provider charges.

```sh
./bin/systemone-mail-filter -mode classify -input testdata/ham.eml
./bin/systemone-mail-filter -mode classify -input testdata/phishing.eml
./bin/systemone-mail-filter -mode filter -input testdata/phishing.eml
```

`-input -` reads stdin. `-envelope-from sender@example.org` optionally supplies
the SMTP sender in these standalone modes. Classification mode exits nonzero
when no classification is available, even if the service's policy is fail-open.

Start the SMTP service with:

```sh
./bin/systemone-mail-filter -config config.example.json
```

The default listener and reinjection destination are literal loopback addresses.
This version intentionally supports only a same-host Postfix deployment. It does
not provide public SMTP, SMTP authentication, or remote relay TLS.

## Classification and policy

One API request asks seven independent questions:

| Dimension | Values |
| --- | --- |
| Spam | Probability from 0 to 1 |
| Primary category | `correspondence`, `transactional_notification`, `newsletter`, `sales_outreach`, `other` |
| Abuse probabilities | `phishing`, `impersonation`, `credential_theft`, `fraudulent_payment_request`, `unsolicited_bulk_content` |

Only the overall spam probability controls tagging. A category or abuse score
alone does not trigger a prefix. Newsletters and sales messages are not
automatically spam. Category distributions and all five abuse probabilities are
retained. No free-text explanation is generated.

Example headers (scores are illustrative):

```text
Subject: [SPAM] Original subject
X-SystemOne-Filter: verdict=spam; model=jev-1.13.0; policy=1; truncated=false
X-SystemOne-Spam: Yes; probability=0.980000
X-SystemOne-Category: transactional_notification
X-SystemOne-Category-Probabilities: correspondence=0.010000;
 transactional_notification=0.960000;
 newsletter=0.010000;
 sales_outreach=0.010000;
 other=0.010000
X-SystemOne-Abuse: phishing=0.860000;
 impersonation=0.970000;
 credential_theft=0.080000;
 fraudulent_payment_request=0.990000;
 unsolicited_bulk_content=0.120000
```

All existing `X-SystemOne-*` headers are removed before fresh results are added.
They cannot be used to bypass classification. An existing matching subject
prefix is not duplicated, including when the original subject uses RFC 2047
encoded words. Missing subjects receive a Subject field when tagged. All other
headers and the MIME body are retained; SMTP performs its normal line-ending
and dot-transparency handling on transmission.

JSON delivery logs include the message's SHA-256, model, policy version, complete
classification, truncation flag, recipient count, duration and delivery result.
They exclude message bodies, subjects, recipient lists, keys and provider response
bodies. The service does not persist message contents or classification results
outside these logs. Protect logs as mail metadata.

## Configuration

See [config.example.json](config.example.json). All fields are optional and fall
back to built-in defaults; unknown fields and invalid values fail startup.

| Setting | Default | Meaning |
| --- | --- | --- |
| `listen` | `127.0.0.1:10025` | Incoming SMTP from Postfix |
| `reinject` | `127.0.0.1:10026` | Postfix listener with filtering disabled |
| `hostname` | `systemone-mail-filter.local` | SMTP greeting/EHLO name |
| `subject_prefix` | `[SPAM]` | Prefix added at or above the threshold |
| `spam_threshold` | `0.95` | Initial threshold; **not calibrated on your mail** |
| `on_error` | `deliver_unmodified` | `deliver_unmodified` or `defer` |
| `api_url` | `https://api.typesafe.ai/v1/systemone` | HTTPS endpoint; HTTP permitted only for loopback test servers |
| `model` | `jev-1.13.0` | Pinned Jev model identifier |
| `api_timeout_seconds` | `5` | Total deadline for each API call |
| `smtp_timeout_seconds` | `60` | SMTP I/O timeout and processing/reinjection deadline |
| `max_message_bytes` | `26214400` | Maximum accepted message size, 25 MiB |
| `max_state_bytes` | `24000` | Maximum serialized classification state, 4096–24000 bytes |
| `max_connections` | `8` | Concurrent SMTP connections; also bounds API concurrency |
| `max_recipients` | `1000` | Recipients per SMTP transaction |
| `circuit_failures` | `5` | Consecutive API failures before pausing requests |
| `circuit_cooldown_seconds` | `30` | API pause following repeated failures |
| `recipient_addresses` | `[]` | Optional exact recipient mailbox allowlist |
| `recipient_domains` | `[]` | Optional exact recipient domain allowlist; no implicit subdomains |

If either recipient allowlist is nonempty, only matching SMTP delivery recipients
are classified. Matching is case-insensitive and uses the envelope, never `To`,
`Cc`, or caller-supplied DSN `ORCPT`. Out-of-scope mail is reinjected byte-for-byte
without parsing, tagging, header changes, or an API request. A transaction mixing
in-scope and out-of-scope recipients returns 451 before classification. Set
`systemone_destination_recipient_limit = 1` in Postfix when using a scoped filter;
Postfix then manages each recipient's queue/retry independently. An empty
allowlist retains the original classify-all behaviour. Standalone CLI modes are
explicit classification tools and do not apply SMTP recipient scope.

`deliver_unmodified` leaves the **subject and body** unchanged on API failure,
timeout, malformed API response, or MIME extraction failure. It still replaces
our diagnostic headers with `verdict=unclassified` and `X-SystemOne-Spam: Unknown`.
It does not mean byte-for-byte delivery of the original headers. `defer` returns
SMTP 451 instead, leaving Postfix to retry. Invalid outer message headers always
defer because the filter cannot safely replace potentially forged verdicts.

Reinjection errors **always** return 451, including downstream permanent errors.
All recipients must be accepted before DATA is sent. The original sender,
including the empty bounce sender, recipients, SMTPUTF8 flag, and DSN parameters
are passed on. Required DSN support is checked rather than silently dropping
notification options. The filter returns success only after reinjection's final
DATA acknowledgement. Like SMTP generally, losing that acknowledgement can cause
a duplicate on retry; this is not an exactly-once delivery system. Postfix's
normal queue lifetime and expiry handling still apply.

There are no in-request retries: transient errors use the configured error
policy, and repeated failures open the circuit breaker. A provider rate limit is
handled like other API errors. Set Postfix transport concurrency within the API
capacity and observe latency/rate-limit logs before increasing throughput.

## Message extraction and limits

The classifier receives the envelope sender; selected **untrusted** headers;
decoded plain text and HTML text; extracted link targets; and attachment names
and content types. MIME parsing supports multipart messages, base64,
quoted-printable, RFC 2047 headers, and common character sets. HTML links are
extracted without opening them. No URL, image, or attachment is fetched or
executed.

MIME nesting is bounded to 16 levels and 128 parts; outer headers to 256 KiB.
Attachment contents, attached messages, images, encrypted content, and OCR are
not inspected. Both plain and HTML alternatives contribute within one byte
budget; earlier parts can consume the budget. Oversized extracts are truncated
and marked in the result. A classification of a truncated or image-only message
is not proof that omitted content is safe.

The SMTP recipient list and `To` header are excluded from API input, but bodies,
sender fields and URLs may still contain personal or confidential data. Using
the hosted API sends that extracted content to TypeSafe. Review the provider's
retention terms for your deployment.

The filter does not verify SPF, DKIM or DMARC and does not trust arbitrary
`Authentication-Results` headers. Keep authentication and malware scanning in
your existing mail pipeline. Changing a signed Subject can invalidate the
original DKIM signature. Perform incoming authentication before tagging; plan
how trusted results are conveyed to downstream systems and, if needed, sign
outbound mail after modification. Preserving a DKIM header does not preserve its
validity after a Subject change.

Prompts treat email as untrusted data, but this is not a guarantee against
adversarial classification. Evaluate real ham/spam, local languages, subscribed
newsletters, invoices, and prompt-injection attempts before relying on the
threshold. Synthetic smoke tests establish API integration, not production
accuracy. Model/policy changes require re-evaluation.

## Postfix integration

Example fragments are in [deploy/postfix/master.cf.example](deploy/postfix/master.cf.example).
They are **not installed automatically**. Merge them with your existing service
definitions, preserving your TLS, authentication, relay and access restrictions.
If a content filter already exists, explicitly design the filter chain before
changing its transport.

The example applies filtering to the public inbound SMTP service only, rather
than globally to submission or reinjected mail. It postpones address mappings
until reinjection so aliases/BCC are not expanded twice. If you already use
`receive_override_options`, merge the options for each stage.

The dedicated reinjection listener must remain bound to loopback, must disable
`content_filter`, and must permit only local clients. It disables repeated
header/body checks and milters. It is not a public relay. Upstream SMTP clients
must never be allowed to reach it directly.

Ensure the original Postfix `message_size_limit` fits within the filter's limit,
allowing room for headers Postfix adds before filtering. The reinjection listener
needs additional headroom for classification headers (the example allows 1 MiB
beyond the filter limit). Oversized messages can otherwise bounce or remain
deferred. Keep the transport's recipient limit no greater than `max_recipients`.

Before cutover: test the standalone CLI, start the filter, verify the reinjection
listener, validate with `postfix check`, then reload Postfix and send a controlled
message end-to-end. Confirm queue drain and final mailbox headers. To bypass the
filter for newly received messages, remove the inbound `content_filter` override
and reload. Already queued filtered messages retain their transport assignment;
keep the filter available while they drain or explicitly requeue selected IDs
after reviewing the effects. Do not disable filtering on the public listener by
accident when editing the reinjection service.

A hardened [systemd unit](deploy/systemone-mail-filter.service) is provided. It expects the
binary at `/usr/local/bin/systemone-mail-filter`, config at `/etc/systemone-mail-filter/config.json`,
and a root-owned mode-0600 `/etc/systemone-mail-filter/jev.env` containing `JEV_KEY=...`.
Systemd reads the environment file before launching the dynamically allocated
service user. No daemon installation or Postfix changes are performed by this
repository's build commands.

## References

- [Postfix after-queue content filtering](https://www.postfix.org/FILTER_README.html)
- [Jev API quick start](https://docs.typesafe.ai/introduction/quickstart)
- [Jev question primitives](https://docs.typesafe.ai/primitives)
- [Jev model capabilities and identifiers](https://docs.typesafe.ai/models)
