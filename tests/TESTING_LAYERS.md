# Testing Layers in Lazeport

## 1. Unit Tests

**Location**: `tests/test_*.py`  
**What**: Test individual functions/classes in isolation  
**Example**: `test_severity_rubric.py` - tests severity extraction logic  
**Run**: `pytest tests/test_severity_rubric.py -v`

## 2. API Integration Tests

**Location**: `tests/test_*.py`  
**What**: Test API endpoints with real database, no browser  
**Example**: `tests/test_cvss_api.py` - tests CVSS field persistence via API  
**Run**: `pytest tests/test_cvss_api.py -v`

## Running Tests

```bash
pytest                    # Sequential execution (recommended)
pytest -v                 # Verbose output
pytest --cov              # With coverage report
```

**Note**: Parallel execution with `pytest -n auto` is not currently supported due to SQLite database locking. Run tests sequentially.

## Test Naming Convention

| Type | File Pattern | Example | Description |
|------|--------------|---------|-------------|
| Unit | `test_<module>.py` | `test_structurer.py` | Tests `app/services/structurer.py` |
| API Integration | `test_<feature>_api.py` | `test_cvss_api.py` | Tests API endpoints for CVSS |

## When to Use Each

### Use Unit Tests When

- Testing pure functions (input → output)
- Testing data transformations
- Testing validation logic
- No external dependencies needed

### Use API Integration Tests When

- Testing API request/response contracts
- Testing database persistence
- Testing business logic that spans multiple layers
- NO UI testing
