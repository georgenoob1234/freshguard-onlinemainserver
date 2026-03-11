
````text
You are working inside one specific service repository of a larger modular system.

Your task is to create a new Markdown documentation file for THIS service that explains the service completely and clearly.

Important:
- First inspect the actual codebase of the current repository before writing anything.
- Do not guess architecture from generic assumptions if the code shows something different.
- Base the document on the real implementation that exists right now.
- If something is missing in code, explicitly say it is "not implemented yet" instead of inventing it.
- The result should be written as a serious technical documentation file that another developer can read to fully understand this service.

## Goal

Create a comprehensive Markdown file, for example one of:
- `SERVICE_ARCHITECTURE.md`
- `docs/architecture.md`
- `docs/service_overview.md`

Choose whichever location best matches the repo structure.

The document must explain:
- what this service does
- why it exists
- how it fits into the wider system
- its architecture and internal modules
- request/response flow
- configuration
- API
- dependencies
- runtime behavior
- error handling
- logging
- limitations
- what is implemented vs not implemented

## What you must do first

1. Inspect the repository structure.
2. Read the main entrypoint(s), config, models, routes, service clients, core logic, and README if present.
3. Identify:
   - framework used
   - main modules
   - public endpoints
   - env vars / config
   - internal data flow
   - important background tasks / workers / schedulers / websocket flows if they exist
   - storage used (memory / files / sqlite / postgres / etc.)
   - external services this service talks to or depends on
4. Only after inspection, write the markdown file.

## Required structure of the Markdown file

Use a clean structure like this:

# <Service Name>

## 1. Purpose
Explain in plain language:
- what the service is responsible for
- what it is not responsible for
- whether it is passive or active in the overall architecture
- how it fits into the larger system

## 2. Role in Overall System
Describe how this service interacts with the other services.
Include a simple architecture explanation in text form.
If useful, include a small Mermaid diagram such as:

```mermaid
flowchart LR
    A[Caller / Upstream Service] --> B[This Service]
    B --> C[Downstream Service]
````

Only include the diagram if it reflects the actual repo behavior.

## 3. High-Level Architecture

Explain:

* main layers / folders / modules
* what each folder or module does
* how responsibility is split
* where API handling, business logic, models, config, and integrations live

If appropriate, include a repo tree like:

```text
app/
  api.py
  config.py
  models.py
  services/
  core/
  ...
```

But only if it reflects the actual structure.

## 4. Request / Execution Flow

Describe the full flow of the service step by step.
Examples:

* how a request enters
* how it is validated
* what internal logic runs
* what external services are called
* how a response is returned
* any async/background behavior
* any state transitions if relevant

If there are multiple important flows, split them:

* normal flow
* fallback flow
* failure flow
* startup flow
* websocket flow
* publish flow
* etc.

## 5. API Contract

Document all public endpoints actually implemented in the repo.

For each endpoint include:

* method
* path
* purpose
* request body / params
* response shape
* possible status codes
* important notes

If Pydantic models or schemas exist, reflect them accurately.

## 6. Configuration

List all important configuration values and environment variables actually used by the code.
For each one explain:

* variable name
* default value if any
* what it controls
* any important production notes

## 7. Internal Data Models

Explain the most important models / schemas / DTOs:

* request models
* response models
* domain objects
* stored entities if applicable

Only summarize the important ones; do not dump raw code.

## 8. External Dependencies

Document external dependencies such as:

* other microservices
* databases
* files
* websocket peers
* object/blob storage
* hardware devices
* third-party libraries if critical to behavior

Explain what this service expects from them.

## 9. State / Storage

Explain whether the service is:

* stateless
* in-memory stateful
* file-backed
* database-backed

Document:

* what data is stored
* where it is stored
* what is transient vs persistent
* cleanup / retention if implemented

## 10. Error Handling and Resilience

Explain:

* validation failures
* upstream/downstream service failures
* retries
* timeouts
* deduplication
* fallback behavior
* what happens on partial failures

Be precise and grounded in code.

## 11. Logging / Observability

Explain:

* what gets logged
* whether logs are structured
* whether there is journaling / metrics / health endpoints
* correlation ids / session ids / scan ids / request ids if used

## 12. Security / Access Control

If implemented, describe:

* auth method
* tokens / API keys
* role checks
* store isolation / tenant isolation
* permissions
* admin endpoints
  If not implemented, explicitly say so.

## 13. Current Limitations / Known Gaps

Add an honest section listing:

* TODO-level gaps visible from the code
* stubs
* temporary compatibility behavior
* places where implementation is partial
* operational risks / technical debt

Do not invent random problems; only include issues grounded in the actual codebase.

## 14. How to Run and Test

Summarize:

* how to run locally
* how to run with Docker if present
* healthcheck endpoint
* basic test command
* any required setup

## 15. Summary

End with a concise summary of what this service currently does in the system.

## Writing requirements

* Write in clean technical English.
* Be explicit, structured, and readable.
* Prefer explanation over code dumping.
* Do not copy large code blocks unless necessary.
* Use short examples where helpful.
* Keep it grounded in the actual implementation.
* If the current README is weak or outdated, create the new file from the code, not from the old README alone.
* If useful, mention where implementation and documentation differ.

## Extra requirement

After creating the markdown file, also give me a short summary in chat of:

1. what file you created
2. what sections it contains
3. any important mismatches or missing pieces you noticed in the current service implementation

