# AI Code Review Agent

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.109.0-009688.svg)](https://fastapi.tiangolo.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Test Coverage](https://img.shields.io/badge/coverage-90%2B-brightgreen.svg)](https://pytest.org)

An AI-powered code review agent with a multi-agent architecture that provides comprehensive code analysis for quality, security, and testing.

## 🚀 Features

- **Multi-Agent Architecture**: Specialized agents for different aspects of code review
  - **Quality Agent**: Code quality analysis using ruff and pylint
  - **Security Agent**: Vulnerability detection using bandit with OWASP mapping
  - **Testing Agent**: Test coverage analysis and suggestions
  - **Orchestrator**: Coordinates agents and aggregates results

- **AI-Powered Insights**: OpenAI GPT integration for intelligent suggestions
  - Contextual code improvement suggestions
  - Plain language vulnerability explanations
  - Smart test case generation

- **GitHub Integration**: Direct Pull Request review support
  - Fetch PR details and changed files
  - Post review comments directly to PRs
  - Rate limiting aware

- **RESTful API**: FastAPI-based API with OpenAPI documentation
  - Code snippet analysis
  - GitHub PR analysis
  - Review result retrieval

## 📋 Requirements

- Python 3.11+
- OpenAI API key (optional, for AI features)
- GitHub token (optional, for PR integration)

## 🛠️ Installation

### Using pip

```bash
# Clone the repository
git clone https://github.com/university/ai-code-review-agent.git
cd ai-code-review-agent

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Copy and configure environment variables
cp env.example .env
# Edit .env with your API keys
```

### Using Docker

```bash
# Build the image
docker build -t ai-code-review-agent .

# Run with environment variables
docker run -p 8000:8000 \
  -e OPENAI_API_KEY=your_key \
  -e GITHUB_TOKEN=your_token \
  ai-code-review-agent
```

### Using Docker Compose

```bash
# Copy environment file
cp env.example .env
# Edit .env with your configuration

# Start the service
docker-compose up -d
```

## ⚙️ Configuration

Create a `.env` file with the following variables:

```env
# Required for AI features
OPENAI_API_KEY=your_openai_api_key_here

# Required for GitHub integration
GITHUB_TOKEN=your_github_token_here

# Optional settings
LOG_LEVEL=INFO
DEBUG=false
PORT=8000
```

## 🚀 Usage

### Starting the Server

```bash
# Development mode
uvicorn src.main:app --reload --port 8000

# Production mode
uvicorn src.main:app --host 0.0.0.0 --port 8000
```

### API Endpoints

#### Review Code Snippet

```bash
curl -X POST "http://localhost:8000/api/v1/review/code" \
  -H "Content-Type: application/json" \
  -d '{
    "code": "def hello():\n    print(\"Hello, World!\")",
    "file_path": "example.py",
    "language": "python"
  }'
```

#### Review GitHub PR

```bash
curl -X POST "http://localhost:8000/api/v1/review/github" \
  -H "Content-Type: application/json" \
  -d '{
    "repo_owner": "octocat",
    "repo_name": "hello-world",
    "pr_number": 42,
    "post_review": false
  }'
```

#### Get Review Results

```bash
curl "http://localhost:8000/api/v1/review/{review_id}"
```

#### Health Check

```bash
curl "http://localhost:8000/health"
```

### Python Client Example

```python
import httpx

async def review_code(code: str) -> dict:
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "http://localhost:8000/api/v1/review/code",
            json={
                "code": code,
                "file_path": "example.py",
                "language": "python"
            }
        )
        return response.json()

# Usage
result = await review_code("def add(a, b): return a + b")
print(f"Score: {result['overall_score']}")
print(f"Findings: {len(result['findings'])}")
```

## 📖 API Documentation

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc
- **OpenAPI JSON**: http://localhost:8000/openapi.json

For detailed API documentation, see [docs/API.md](docs/API.md).

## 🧪 Testing

### Running Tests

```bash
# Run all tests with coverage
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/test_agents/test_quality_agent.py

# Run with coverage report
pytest --cov=src --cov-report=html

# Run only unit tests
pytest -m unit

# Run without slow tests
pytest -m "not slow"
```

### Coverage Report

After running tests, view the HTML coverage report:
- Open `coverage_html/index.html` in your browser

Target coverage: **90%+**

## 🏗️ Project Structure

```
ai-code-review-agent/
├── src/
│   ├── __init__.py
│   ├── main.py              # FastAPI application
│   ├── config.py            # Configuration management
│   ├── agents/              # Code review agents
│   │   ├── base_agent.py    # Abstract base class
│   │   ├── quality_agent.py # Quality analysis
│   │   ├── security_agent.py# Security scanning
│   │   ├── testing_agent.py # Test coverage
│   │   └── orchestrator.py  # Agent coordination
│   ├── analyzers/           # Analysis tools
│   │   ├── static_analyzer.py # ruff, pylint, bandit
│   │   └── llm_analyzer.py    # OpenAI integration
│   ├── models/              # Data models
│   │   └── schemas.py       # Pydantic schemas
│   ├── services/            # Business logic
│   │   ├── github_service.py # GitHub API
│   │   └── review_service.py # Review orchestration
│   └── utils/               # Utilities
│       └── helpers.py       # Helper functions
├── tests/                   # Test suite
├── docs/                    # Documentation
├── requirements.txt         # Dependencies
├── Dockerfile              # Container definition
└── docker-compose.yml      # Container orchestration
```

## 🔧 Development

### Setting Up Development Environment

```bash
# Install development dependencies
pip install -r requirements.txt
pip install black isort mypy

# Format code
black src tests
isort src tests

# Type checking
mypy src

# Linting
ruff check src tests
```

### Adding New Agents

1. Create a new file in `src/agents/`
2. Inherit from `BaseAgent`
3. Implement the `analyze()` method
4. Register in `Orchestrator.__init__()`

Example:

```python
from src.agents.base_agent import BaseAgent
from src.models.schemas import Finding

class MyCustomAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="MyCustomAgent",
            description="Custom analysis agent"
        )
    
    async def analyze(self, code: str, file_path: str, language: str) -> list[Finding]:
        findings = []
        # Your analysis logic here
        return findings
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👥 Team Members

**SEN0414 - Software Engineering Final Project**

| Name | Student ID | Role |
|------|------------|------|
| [Team Member 1] | [ID] | [Role] |
| [Team Member 2] | [ID] | [Role] |
| [Team Member 3] | [ID] | [Role] |
| [Team Member 4] | [ID] | [Role] |

## 🙏 Acknowledgments

- [FastAPI](https://fastapi.tiangolo.com/) - Modern Python web framework
- [OpenAI](https://openai.com/) - AI language models
- [Ruff](https://github.com/astral-sh/ruff) - Fast Python linter
- [Pylint](https://pylint.org/) - Python static analysis
- [Bandit](https://bandit.readthedocs.io/) - Security linter
- [Pydantic](https://docs.pydantic.dev/) - Data validation

---

Made with ❤️ for SEN0414 Final Project
