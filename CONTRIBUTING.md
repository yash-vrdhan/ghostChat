# Contributing

## Setup
1. Create a virtual environment
2. Install dependencies:
   - `pip install -e .[dev]` or
   - `poetry install`
3. Run tests: `poetry run pytest -q`

## Test Expectations
- Keep crypto and transport tests passing
- Add/adjust tests when protocol behavior changes
- If socket bind is restricted in your environment, transport tests may be skipped by design

## Ground Rules
- Keep changes focused and reviewable
- Preserve protocol compatibility unless explicitly changing version/behavior
- Treat transport/ACK/crypto flow as core contract: update docs + tests with any changes

## Pull Requests
- Include concise summary of behavior changes
- Include manual test steps (`two terminals`, commands used, observed output)
- Call out backward-compatibility impact
- Ensure CI is green
