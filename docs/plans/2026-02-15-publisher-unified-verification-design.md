# Publisher API Unified Verification Design

## Goals
- Add order-level and token-level query coverage for one-time purchases and subscriptions.
- Provide a unified verification entry point to reduce caller branching.
- Keep backward compatibility with existing public APIs.

## Non-Goals
- Breaking changes to existing method signatures.
- Introducing new external dependencies.

## Architecture
- Keep `publisher.Service` as the public entry point.
- Add new query methods alongside existing verification methods.
- Add a unified verification method that routes based on request type.

## Components
- `publisher.Service`:
  - `QueryPurchase` for order-level and token-level one-time product queries.
  - `QuerySubscription` for order-level and token-level subscription queries.
  - `Verify` (or `VerifyUnified`) to route verification based on request data.
- `publisher/types.go` (new or existing types file):
  - `PurchaseQuery`, `SubscriptionQuery`, `VerifyRequest`, `VerifyResult`.

## Data Flow
1. Caller builds `VerifyRequest` or a specific query struct.
2. `Service` routes to the right Google Play Publisher API endpoint.
3. Token-level calls reuse existing `VerifyPurchase`/`VerifySubscriptions` logic.
4. Order-level calls use new request paths; results returned in official API types.
5. Unified verification returns `VerifyResult` with type indicator and raw response.

## Error Handling
- Validate required fields (package name, token/order id).
- Return a dedicated routing error when unified verification cannot determine type.
- Distinguish not-found from API errors (e.g., `ErrNotFound`).

## Testing
- Parameter validation tests for each new method.
- Routing tests for the unified verification entry point.
- Path/method validation for order-level and token-level requests.
- Error propagation tests, including not-found behavior.

## Rollout
- Add new APIs without changing existing ones.
- Update README API table and examples after implementation.
