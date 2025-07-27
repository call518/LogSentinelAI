# Contributing to LogSentinelAI

Thank you for your interest in contributing to LogSentinelAI! This document provides guidelines and information for contributors.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Environment](#development-environment)
- [Project Structure](#project-structure)
- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Release Process](#release-process)

## 🤝 Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). By participating, you are expected to uphold this code.

## 🚀 Getting Started

### Prerequisites

- Python 3.11 or higher
- Git
- UV package manager (recommended) or pip
- Docker (for testing with Elasticsearch)

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/LogSentinelAI.git
   cd LogSentinelAI
   ```

## 🛠 Development Environment

### Using UV (Recommended)

UV is the recommended package manager for this project:

```bash
# Install UV if you haven't already
curl -LsSf https://astral.sh/uv/install.sh | sh

# Create virtual environment and install dependencies
uv sync

# Install development dependencies
uv sync --extra dev

# Activate the virtual environment
source .venv/bin/activate  # Linux/macOS
# or
.venv\Scripts\activate     # Windows
```

### Using pip

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate     # Windows

# Install in development mode
pip install -e ".[dev]"
```

### Configuration

1. Copy the configuration template:
   ```bash
   cp config.template config
   ```

2. Edit the `config` file with your settings:
   - Set up your LLM provider (OpenAI, Ollama, or vLLM)
   - Configure API keys if using OpenAI
   - Adjust other settings as needed

### GeoIP Database

Download the GeoIP database for location enrichment:

```bash
# Using the built-in utility
logsentinelai-geoip-download

# The database is automatically downloaded to ~/.logsentinelai/ on first use
```

## 📁 Project Structure

```
LogSentinelAI/
├── src/logsentinelai/           # Main package
│   ├── analyzers/               # Log type analyzers
│   │   ├── httpd_access.py      # HTTP access log analyzer
│   │   ├── httpd_apache.py      # Apache error log analyzer
│   │   ├── linux_system.py      # Linux system log analyzer
│   │   └── tcpdump_packet.py    # Network packet analyzer
│   ├── core/                    # Core functionality
│   │   ├── commons.py           # Common utilities
│   │   ├── config.py            # Configuration management
│   │   ├── elasticsearch.py     # Elasticsearch integration
│   │   ├── geoip.py             # GeoIP functionality
│   │   ├── llm.py               # LLM provider interface
│   │   ├── monitoring.py        # Progress monitoring
│   │   ├── prompts.py           # LLM prompts
│   │   ├── ssh.py               # SSH remote access
│   │   └── utils.py             # Utility functions
│   ├── utils/                   # Additional utilities
│   │   └── geoip_downloader.py  # GeoIP database downloader
│   └── cli.py                   # Command line interface
├── sample-logs/                 # Sample log files for testing
├── img/                         # Documentation images
├── config.template              # Configuration template
├── pyproject.toml              # Project configuration
├── uv.lock                     # UV lock file
├── .github/workflows/          # GitHub Actions workflows
├── Kibana-*.ndjson             # Kibana dashboard exports
└── README.md                   # Project documentation
```

## 🔄 Development Workflow

### 1. Create a Feature Branch

```bash
git checkout -b feature/your-feature-name
```

### 2. Make Your Changes

- Follow the coding standards below
- Add tests for new functionality (note: test framework is configured but tests directory needs to be created)
- Update documentation as needed
- Test your changes locally

### 3. Test Your Changes

```bash
# Test specific analyzer
logsentinelai-httpd-access --help

# Test with sample data
logsentinelai-httpd-access sample-logs/access-100.log

# Test other analyzers
logsentinelai-httpd-apache sample-logs/apache-100.log
logsentinelai-linux-system sample-logs/linux-100.log
logsentinelai-tcpdump sample-logs/tcpdump-packet-39-multi-line.log
```

### 4. Commit Your Changes

```bash
git add .
git commit -m "feat: add new feature description"
```

Follow [Conventional Commits](https://www.conventionalcommits.org/) format:
- `feat:` new feature
- `fix:` bug fix
- `docs:` documentation changes
- `style:` formatting changes
- `refactor:` code refactoring
- `test:` adding tests
- `chore:` maintenance tasks

## 📝 Coding Standards

### Python Style Guide

This project follows PEP 8 with some modifications:

- **Line length**: 88 characters (Black default)
- **Indentation**: 4 spaces
- **Quote style**: Double quotes preferred
- **Import sorting**: isort with Black profile

### Code Formatting

Use the following tools (already configured in `pyproject.toml`):

```bash
# Format code with Black
black src/

# Sort imports with isort
isort src/

# Type checking with mypy
mypy src/

# Linting with flake8
flake8 src/
```

### Documentation

- Use docstrings for all public functions and classes
- Follow Google docstring format
- Include type hints for all function signatures
- Update README.md for significant changes

### Error Handling

- Use specific exception types
- Provide helpful error messages
- Log errors appropriately
- Handle edge cases gracefully

## 🧪 Testing

### Current Test Status

**Note**: This project is currently configured for testing but does not yet have a `tests/` directory or test files implemented. The testing framework is ready to use with pytest configuration in `pyproject.toml`.

### Testing Configuration

The project includes testing tools in development dependencies:
- `pytest>=7.0` - Testing framework
- `pytest-asyncio>=0.21.0` - Async testing support
- `pytest-cov>=4.0` - Coverage reporting

### Setting Up Tests (For Contributors)

If you're adding the first tests:

```bash
# Create tests directory
mkdir tests

# Create __init__.py
touch tests/__init__.py

# Create test files following pytest conventions
touch tests/test_analyzers.py
touch tests/test_core.py
```

### Running Tests (Once Implemented)

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=logsentinelai --cov-report=term-missing

# Run specific test file
pytest tests/test_specific.py

# Run tests verbosely
pytest -v
```

### Manual Testing

Until automated tests are implemented, use manual testing:

```bash
# Test CLI help
logsentinelai --help

# Test analyzers with sample data
logsentinelai-httpd-access sample-logs/access-100.log
logsentinelai-httpd-apache sample-logs/apache-100.log
logsentinelai-linux-system sample-logs/linux-100.log
logsentinelai-tcpdump sample-logs/tcpdump-packet-39-multi-line.log

# Test GeoIP downloader
logsentinelai-geoip-download
```

### Test Guidelines for New Contributors

When adding tests:

1. **Create test files** following `test_*.py` naming convention
2. **Test both success and failure cases**
3. **Mock external dependencies** (LLM APIs, Elasticsearch)
4. **Use sample log files** from `sample-logs/` directory
5. **Follow pytest best practices**
6. **Ensure good test coverage** for new code

## 📤 Submitting Changes

### Pull Request Process

1. **Update documentation**: Ensure README.md and other docs are updated
2. **Add tests**: Include tests for new functionality
3. **Check formatting**: Run Black, isort, and mypy
4. **Test thoroughly**: Ensure all tests pass
5. **Create PR**: Submit a pull request with a clear description

### Pull Request Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Performance improvement
- [ ] Code refactoring

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests pass
- [ ] Manual testing completed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] Tests added/updated
```

## 🔧 Development Tips

### Adding New Log Analyzers

1. Create new analyzer in `src/logsentinelai/analyzers/`
2. Follow existing analyzer patterns
3. Define Pydantic models for structured output
4. Create appropriate LLM prompts
5. Add CLI entry point in `pyproject.toml`
6. Update documentation

### LLM Integration

- Test with multiple LLM providers
- Consider token limits and costs
- Implement proper error handling
- Use structured generation with Outlines
- Validate outputs with Pydantic

### Elasticsearch Integration

- Follow ILM (Index Lifecycle Management) patterns
- Use appropriate field mappings
- Consider index templates
- Test with different ES versions

## 🚀 Release Process

### Versioning

This project uses [Semantic Versioning](https://semver.org/):
- **MAJOR**: Incompatible API changes
- **MINOR**: Backward-compatible functionality
- **PATCH**: Backward-compatible bug fixes

### Current Release Tags

Recent releases follow numeric versioning without 'v' prefix:
- `0.2.3` (latest)
- `0.2.2`
- `0.2.1`
- `0.2.0`
- `0.1.9`

### Release Workflow

1. **Update version**: Version is automatically set from Git tags during build
2. **Create numeric tag**: 
   ```bash
   git tag 0.2.4
   ```
3. **Push tag**: 
   ```bash
   git push origin 0.2.4
   ```
4. **GitHub Actions**: Automatically builds and publishes to PyPI
5. **Release notes**: Create GitHub release with changelog

### Automated Publishing

The project uses GitHub Actions for automated publishing:
- **Trigger**: Git tags matching pattern `*` (any tag)
- **Process**: Build → TestPyPI → PyPI
- **Configuration**: `.github/workflows/pypi-publish.yml`

The workflow:
1. Extracts version from tag name (`VERSION=${GITHUB_REF##refs/tags/}`)
2. Injects version into `pyproject.toml`
3. Builds distributions with `python -m build`
4. Publishes to TestPyPI first
5. Publishes to PyPI if TestPyPI succeeds

### Tag Format

**Important**: This project uses **numeric tags only** (e.g., `0.2.4`), not prefixed with 'v'.

## 🤔 Questions and Support

### Getting Help

- **Issues**: Report bugs and request features via GitHub Issues
- **Discussions**: Use GitHub Discussions for questions
- **Email**: Contact maintainer at call518@gmail.com

### Issue Templates

When reporting issues:

1. **Bug reports**: Include steps to reproduce, expected behavior, actual behavior
2. **Feature requests**: Describe the problem and proposed solution
3. **Questions**: Provide context and what you've already tried

## 📜 License

By contributing to LogSentinelAI, you agree that your contributions will be licensed under the MIT License.

## 🙏 Recognition

Contributors will be recognized in:
- GitHub contributors list
- Release notes for significant contributions
- Project documentation

Thank you for contributing to LogSentinelAI! 🎉