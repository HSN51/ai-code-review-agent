# AI Code Review Agent - API Documentation

## Overview

The AI Code Review Agent provides a RESTful API for automated code review. This document describes all available endpoints, request/response formats, and usage examples.

**Base URL**: `http://localhost:8000`

**API Version**: v1

## Authentication

Currently, the API does not require authentication for code review endpoints. GitHub integration requires a `GITHUB_TOKEN` environment variable to be set.

## Content Types

All endpoints accept and return JSON:
- Request: `Content-Type: application/json`
- Response: `Content-Type: application/json`

---

## Endpoints

### Health Check

Check the health status of the API and its dependencies.

**GET** `/health`

#### Response

```json
{
  "status": "healthy",
  "version": "1.0.0",
  "timestamp": "2024-01-15T10:30:00.000Z",
  "openai_configured": true,
  "github_configured": true
}
```

#### Response Fields

| Field | Type | Description |
|-------|------|-------------|
| status | string | Service status ("healthy") |
| version | string | API version |
| timestamp | datetime | Current timestamp |
| openai_configured | boolean | Whether OpenAI API is configured |
| github_configured | boolean | Whether GitHub API is configured |

---

### Review Code Snippet

Analyze a code snippet for quality, security, and testing issues.

**POST** `/api/v1/review/code`

#### Request Body

```json
{
  "code": "def hello():\n    print('Hello, World!')",
  "file_path": "example.py",
  "language": "python"
}
```

#### Request Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| code | string | Yes | - | Source code to analyze |
| file_path | string | No | "untitled.py" | Virtual file path for context |
| language | string | No | "python" | Programming language |

#### Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "findings": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440001",
      "file_path": "example.py",
      "line_number": 1,
      "severity": "low",
      "category": "style",
      "message": "Function lacks docstring",
      "suggestion": "Add a docstring to describe the function's purpose",
      "agent_name": "QualityAgent",
      "rule_id": "ruff:D103",
      "confidence": 0.9
    }
  ],
  "summary": "Code review completed. Found 1 issue (1 low severity). Score: 98/100",
  "timestamp": "2024-01-15T10:30:00.000Z",
  "overall_score": 98.0,
  "status": "completed",
  "files_analyzed": 1,
  "total_lines": 2,
  "execution_time": 1.5,
  "agent_summaries": {
    "QualityAgent": "Found 1 low severity issues",
    "SecurityAgent": "No issues found",
    "TestingAgent": "No issues found"
  }
}
```

#### Response Fields

| Field | Type | Description |
|-------|------|-------------|
| id | UUID | Unique review identifier |
| findings | array | List of findings |
| summary | string | Human-readable summary |
| timestamp | datetime | Review completion time |
| overall_score | float | Score from 0-100 |
| status | string | Review status |
| files_analyzed | integer | Number of files analyzed |
| total_lines | integer | Total lines of code |
| execution_time | float | Time in seconds |
| agent_summaries | object | Summary per agent |

---

### Review GitHub Pull Request

Analyze a GitHub Pull Request for quality, security, and testing issues.

**POST** `/api/v1/review/github`

#### Request Body

```json
{
  "repo_owner": "octocat",
  "repo_name": "hello-world",
  "pr_number": 42,
  "include_comments": false,
  "post_review": false
}
```

#### Request Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| repo_owner | string | Yes | - | Repository owner/organization |
| repo_name | string | Yes | - | Repository name |
| pr_number | integer | Yes | - | Pull request number |
| include_comments | boolean | No | false | Include existing PR comments |
| post_review | boolean | No | false | Post review to GitHub |

#### Response

Same format as code review response, with PR-specific summary.

#### Errors

| Status Code | Description |
|-------------|-------------|
| 401 | GitHub token not configured |
| 404 | PR not found |
| 500 | Internal server error |

---

### Get Review Results

Retrieve results of a previously completed review.

**GET** `/api/v1/review/{review_id}`

#### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| review_id | UUID | Review identifier |

#### Response

Same format as code review response.

#### Errors

| Status Code | Description |
|-------------|-------------|
| 404 | Review not found |
| 422 | Invalid UUID format |

---

### List Agents

Get information about available code review agents.

**GET** `/api/v1/agents`

#### Response

```json
{
  "agents": [
    {
      "name": "QualityAgent",
      "description": "Analyzes code quality including style, complexity, and best practices"
    },
    {
      "name": "SecurityAgent",
      "description": "Analyzes security vulnerabilities and maps to OWASP categories"
    },
    {
      "name": "TestingAgent",
      "description": "Analyzes test coverage and suggests missing test cases"
    }
  ]
}
```

---

### Get Configuration

Get current configuration status (non-sensitive info only).

**GET** `/api/v1/config`

#### Response

```json
{
  "openai_configured": true,
  "openai_model": "gpt-4",
  "github_configured": true,
  "log_level": "INFO",
  "cache_ttl": 3600
}
```

---

## Data Models

### Finding

Represents a single issue found during code review.

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "file_path": "src/main.py",
  "line_number": 42,
  "end_line_number": 45,
  "column": 0,
  "severity": "high",
  "category": "sql_injection",
  "message": "Possible SQL injection vulnerability detected",
  "suggestion": "Use parameterized queries instead of string concatenation",
  "agent_name": "SecurityAgent",
  "rule_id": "bandit:B608",
  "code_snippet": "query = f\"SELECT * FROM users WHERE id = {user_input}\"",
  "owasp_category": "A03:2021-Injection",
  "confidence": 0.95
}
```

### Severity Levels

| Level | Description |
|-------|-------------|
| critical | Critical issues requiring immediate attention |
| high | High priority issues |
| medium | Medium priority issues |
| low | Low priority issues |
| info | Informational notices |

### Finding Categories

#### Quality Categories
- `code_smell` - Code smells and anti-patterns
- `complexity` - High cyclomatic complexity
- `naming` - Naming convention violations
- `style` - Style and formatting issues
- `duplication` - Code duplication
- `maintainability` - Maintainability issues

#### Security Categories
- `sql_injection` - SQL injection vulnerabilities
- `xss` - Cross-site scripting
- `hardcoded_secret` - Hardcoded credentials
- `insecure_import` - Insecure imports
- `authentication` - Authentication issues
- `authorization` - Authorization issues
- `cryptography` - Cryptographic issues
- `injection` - General injection vulnerabilities

#### Testing Categories
- `missing_test` - Missing test cases
- `low_coverage` - Low test coverage
- `edge_case` - Untested edge cases
- `test_quality` - Test quality issues

---

## Error Responses

All errors follow this format:

```json
{
  "error": "ValidationError",
  "message": "Invalid request body",
  "detail": "code: field required",
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

### Common Error Codes

| Status Code | Error Type | Description |
|-------------|------------|-------------|
| 400 | Bad Request | Invalid request format |
| 401 | Unauthorized | Authentication required |
| 404 | Not Found | Resource not found |
| 422 | Unprocessable Entity | Validation error |
| 500 | Internal Server Error | Server error |

---

## Rate Limiting

The API implements rate limiting for GitHub API calls based on GitHub's rate limits. OpenAI API calls are subject to your OpenAI plan limits.

---

## Examples

### Python

```python
import httpx
import asyncio

async def analyze_code():
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "http://localhost:8000/api/v1/review/code",
            json={
                "code": """
def calculate_sum(numbers):
    total = 0
    for n in numbers:
        total += n
    return total
""",
                "file_path": "calculator.py",
                "language": "python"
            }
        )
        result = response.json()
        
        print(f"Score: {result['overall_score']}/100")
        print(f"Findings: {len(result['findings'])}")
        
        for finding in result['findings']:
            print(f"  [{finding['severity']}] {finding['message']}")
            if finding['suggestion']:
                print(f"    Suggestion: {finding['suggestion']}")

asyncio.run(analyze_code())
```

### JavaScript/TypeScript

```typescript
async function analyzeCode(code: string): Promise<ReviewResult> {
  const response = await fetch('http://localhost:8000/api/v1/review/code', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      code,
      file_path: 'example.py',
      language: 'python',
    }),
  });
  
  return response.json();
}

// Usage
const result = await analyzeCode('def hello(): print("hi")');
console.log(`Score: ${result.overall_score}`);
```

### cURL

```bash
# Review code snippet
curl -X POST "http://localhost:8000/api/v1/review/code" \
  -H "Content-Type: application/json" \
  -d '{
    "code": "query = f\"SELECT * FROM users WHERE id = {id}\"",
    "file_path": "db.py"
  }'

# Review GitHub PR
curl -X POST "http://localhost:8000/api/v1/review/github" \
  -H "Content-Type: application/json" \
  -d '{
    "repo_owner": "octocat",
    "repo_name": "hello-world",
    "pr_number": 1
  }'

# Get review results
curl "http://localhost:8000/api/v1/review/550e8400-e29b-41d4-a716-446655440000"

# Health check
curl "http://localhost:8000/health"
```

---

## OpenAPI Specification

The complete OpenAPI specification is available at:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`
- JSON: `http://localhost:8000/openapi.json`

