# Contributing to LogSentinelAI

Thank you for contributing! This guide covers the essentials for developers.

## 🚀 Quick Setup

### Prerequisites
- Python 3.11+
- Git
- UV package manager (recommended)

### Development Setup
```bash
# Fork and clone
git clone https://github.com/YOUR_USERNAME/LogSentinelAI.git
cd LogSentinelAI

# Install dependencies
uv sync

# Setup config
cp config.template config
# Edit config with your LLM provider settings

# Download GeoIP database
logsentinelai-geoip-download
```

##  Development Workflow

### 1. Create Feature Branch
```bash
git checkout -b feature/your-feature-name
```

### 2. Make Changes & Test
```bash
# Test your changes
logsentinelai-httpd-access sample-logs/access-100.log

# Format code
black src/ && isort src/ && mypy src/
```

### 3. Commit & Push
```bash
git commit -m "feat: description"  # Use Conventional Commits
git push origin feature/your-feature-name
```

### 4. Create Pull Request
Use our [PR template](.github/PULL_REQUEST_TEMPLATE.md) for submissions.

## 📝 Coding Standards

- **Style**: PEP 8, 88 char line length
- **Format**: Black + isort
- **Types**: Type hints required
- **Docs**: Google-style docstrings for public APIs

### Code Quality Check
```bash
black src/          # Format
isort src/          # Sort imports  
mypy src/           # Type check
flake8 src/         # Lint
```

## 🧪 Testing

### Manual Testing
```bash
# Test all analyzers
logsentinelai-httpd-access sample-logs/access-100.log
logsentinelai-httpd-apache sample-logs/apache-100.log
logsentinelai-linux-system sample-logs/linux-100.log
```

### Setting Up Automated Tests
```bash
# Create test structure (if first contributor)
mkdir tests
touch tests/__init__.py tests/test_analyzers.py
```

## 💡 Adding New Analyzers

1. **Create analyzer**: `src/logsentinelai/analyzers/your_analyzer.py`
2. **Follow patterns**: Use Pydantic models + LLM prompts like existing analyzers
3. **Add CLI entry**: Update `pyproject.toml` console scripts
4. **Test thoroughly**: Use sample logs and edge cases
5. **Update docs**: Add usage examples

### Analyzer Template
```python
from pydantic import BaseModel
from ..core.commons import analyze_logs

class YourLogEntry(BaseModel):
    # Define your structured output
    pass

def analyze_your_logs(log_file: str) -> list[YourLogEntry]:
    # Implement using existing patterns
    pass
```

## 🚀 Release Process

- **Versioning**: Semantic versioning (e.g., `0.2.4`)
- **Tags**: Numeric only, no 'v' prefix
- **Publishing**: Automated via GitHub Actions

```bash
git tag 0.2.4
git push origin 0.2.4
```

## 📋 Commit Guidelines

Use [Conventional Commits](https://www.conventionalcommits.org/):
- `feat:` new features
- `fix:` bug fixes  
- `docs:` documentation
- `refactor:` code improvements
- `test:` adding tests
- `chore:` maintenance

## 🤔 Getting Help

- **Issues**: Use [issue template](.github/ISSUE_TEMPLATE.md)
- **Discussions**: GitHub Discussions for questions
- **Email**: call518@gmail.com

## 📜 License

MIT License - contributions will be licensed under the same terms.