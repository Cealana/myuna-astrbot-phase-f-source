# ADR-043: Vision Media Boundary v1

Status: R1 repository-only / inactive / no filesystem implementation

## Decision

Transport download and image-model invocation are separated by a private,
ephemeral media boundary. The boundary owns byte verification and lifecycle; it
does not own identity, conversation, memory, tools, or provider routing.

The v1 lifecycle is:

1. a channel adapter authenticates the event and obtains a bounded stream;
2. an implementation stages verified regular files in a private scope;
3. it returns an opaque ticket with no path or handle;
4. a consumer claims one short-lived, single-read lease per media item;
5. bytes are read through the port with an explicit maximum;
6. all media in the ticket is disposed after consumption, rejection, cancellation,
   or expiry;
7. disposal emits metadata-only receipts.

## Fixed guards

- inactive candidate only;
- private owner and regular-file checks required;
- symbolic links rejected;
- maximum TTL 300 seconds in the example policy;
- exactly one permitted read;
- no persistent copy;
- no remote fetch at this boundary;
- disposal required;
- no local path, file descriptor, URL, question, account identifier, image bytes,
  or credential in tickets, leases, logs, or receipts.

Filesystem-specific secure deletion is not claimed. On SSDs and copy-on-write
storage, overwrite semantics may not be reliable. `secure_disposal_required`
therefore means unlink the private staged object, close all handles, prevent
reuse, and expire its key material if later encryption-at-rest is added; it does
not make an unsupported physical-erasure promise.

## Non-effects

R1 provides types, protocols, deterministic validation, an inactive policy, and
tests only. It does not create a staging directory or system user, download or
decode an image, write a file, start a sweeper, call a provider, connect a
channel, modify capabilities, or change any service.

## Follow-up

The next repository-only step is an authenticated media-delivery extension and
a Fake staging implementation. A real implementation must be content-addressed,
non-following, quota-limited, crash-cleanable, and independently audited before
Telegram Vision Shadow.
