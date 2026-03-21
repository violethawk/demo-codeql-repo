# Contributing to SAGE

## Setup

```bash
git clone <repo>
cd sage
python -m pytest tests/ -v    # verify everything works
python -m sage check           # validate configuration
```

## Adding a new CWE

1. Add a policy entry to `sage/pipeline/policy.py`:
   ```python
   "CWE-XXX": RemediationPolicy(
       cwe="CWE-XXX",
       name="Vulnerability Name",
       action=AUTO_REMEDIATE,  # or REMEDIATE_WITH_REVIEW, ESCALATE, DEFER
       fix_confidence="HIGH",
       sla_hours=24,
       escalation_note="",
   ),
   ```

2. If the action includes remediation, add a handler to `sage/pipeline/execute.py`:
   ```python
   def _fix_cwexxx(file_path: Path, alert: Alert) -> ExecutionResult:
       ...

   _FIX_DISPATCH["CWE-XXX"] = _fix_cwexxx
   ```

3. Add a fixture: `demo/fixtures/sample_alert_xxx.json`

4. Add tests in `tests/test_execute.py`

5. Run `python -m pytest tests/ -v` to verify

## Adding an integration

Integrations live in `sage/integrations/`. Each exposes:
- A typed dataclass contract (request/response)
- A `build_*()` function to assemble the payload
- A `deliver_*()` function with stub + real mode

To add Slack, PagerDuty, Jira, etc., follow the pattern in `notify.py`.

## Running tests

```bash
python -m pytest tests/ -v           # all tests
python -m pytest tests/ -k "cwe89"   # specific tests
python -m coverage run -m pytest tests/ && python -m coverage report
```

## Code style

- Python 3.12+, stdlib only (no pip dependencies)
- Type hints on public functions
- Dataclasses for contracts
- Tests for every pipeline stage
