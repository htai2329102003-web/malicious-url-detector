# 🤝 Contributing to Malicious URL Detector

Cảm ơn bạn đã quan tâm đến việc góp phần cho dự án này! Dưới đây là hướng dẫn chi tiết.

## 📋 Code of Conduct

Chúng tôi cam kết duy trì một cộng đồng welcoming, professional, và respectful.

## 🐛 Báo Cáo Lỗi (Bug Reports)

Khi phát hiện lỗi, vui lòng tạo một GitHub issue với thông tin:

1. **Mô tả lỗi**: Điều gì xảy ra?
2. **Bước tái hiện** (Reproduction steps):
   ```
   1. ...
   2. ...
   3. ...
   ```
3. **Hành vi mong đợi**: Cái gì nên xảy ra
4. **Hành vi thực tế**: Cái gì đã xảy ra
5. **Thông tin môi trường**:
   - OS: Windows/macOS/Linux
   - Python version: 3.8/3.9/3.10/3.11
   - Chrome version: ...
6. **Logs & Error messages**: Nếu có
7. **Screenshots**: Nếu có UI issue

### Ví dụ Issue

```markdown
**Title**: Extension crashes when checking URL with special characters

**Description**: 
The Chrome extension crashes with error when checking URLs containing...

**Steps to reproduce**:
1. Open Chrome extension
2. Paste URL: https://example.com/path?q=你好
3. Click scan button
4. See crash

**Expected**: URL should be checked successfully
**Actual**: Browser console shows error: TypeError: Cannot read property...

**Environment**:
- OS: Windows 10
- Python: 3.10
- Chrome: 120.0.6099.71

**Error Log**:
```
Traceback (most recent call last):
  ...
```

## 💡 Đề Xuất Tính Năng (Feature Requests)

Có ý tưởng mới? Tạo issue với tiêu đề `[FEATURE]`:

```markdown
**Title**: [FEATURE] Support for URL whitelist

**Description**: 
Users should be able to create a whitelist of trusted URLs that...

**Use Case**:
As a user, I want to... so that...

**Proposed Solution**:
- Add whitelist settings in extension popup
- Store whitelist in Chrome storage
- Skip checking URLs in whitelist
```

## 🔧 Development Setup

### 1. Fork & Clone
```bash
git clone https://github.com/YOUR_USERNAME/malicious-url-detector.git
cd malicious-url-detector
git remote add upstream https://github.com/ORIGINAL/malicious-url-detector.git
```

### 2. Create Feature Branch
```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/your-bug-fix
```

### 3. Setup Development Environment
```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install dev dependencies (if available)
pip install pytest pytest-cov black flake8 mypy
```

### 4. Make Changes
- Write clean, readable code
- Follow PEP 8 style guide
- Add docstrings to functions
- Add comments for complex logic

### 5. Testing
```bash
# Run tests (if available)
pytest

# Check code style
flake8 malicious_url_detector/
black --check malicious_url_detector/

# Type checking
mypy malicious_url_detector/
```

### 6. Commit Changes
```bash
# Make atomic commits
git add .
git commit -m "feat: add new feature description"

# Commit message format:
# feat: add new feature
# fix: fix bug
# docs: update documentation
# style: format code
# refactor: refactor code
# test: add tests
# chore: update dependencies
```

### 7. Push & Create Pull Request
```bash
git push origin feature/your-feature-name
```

Then create a Pull Request on GitHub with:

```markdown
## Description
Describe your changes here

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Performance improvement
- [ ] Code refactoring

## Related Issues
Closes #123

## Testing Done
Describe testing performed:
- [ ] Manual testing on Chrome
- [ ] Flask API tested
- [ ] Model accuracy verified

## Checklist
- [ ] Code follows style guidelines
- [ ] Changes documented
- [ ] No breaking changes
- [ ] Tested on Windows/macOS/Linux
```

## 📝 Code Style Guide

### Python Code
```python
# Good
def extract_url_features(url: str) -> dict:
    """
    Extract features from URL.
    
    Args:
        url: The URL to analyze
        
    Returns:
        Dictionary of extracted features
    """
    features = {}
    # Implementation
    return features

# Bad
def extract(url):
    f = {}
    # Implementation
    return f
```

### JavaScript Code
```javascript
// Good
async function checkURL(url) {
    try {
        const response = await fetch(API_URL, {
            method: 'POST',
            body: JSON.stringify({ url })
        });
        return await response.json();
    } catch (error) {
        console.error('Error checking URL:', error);
        throw error;
    }
}

// Bad
function checkURL(u) {
    let r = fetch(API_URL, { method: 'POST', body: JSON.stringify({ url: u }) });
    return r.json();
}
```

## 📚 Documentation

- Update README.md for user-facing changes
- Add docstrings for functions/classes
- Comment complex algorithms
- Update CHANGELOG.md if exists

## 🚀 Pull Request Process

1. **Update branch**: `git pull upstream main`
2. **Rebase if needed**: `git rebase upstream/main`
3. **Create PR** with clear description
4. **Wait for review**: Maintainers will review
5. **Address feedback**: Make requested changes
6. **Squash commits** if asked: `git rebase -i HEAD~N`
7. **Merge**: Once approved

## ⚡ Quick Contribution Ideas

Good first issues for new contributors:
- Add more URL features
- Improve error handling
- Update documentation
- Add unit tests
- Optimize performance
- Add new TLDs to suspicious list
- Improve UI/UX

## 📖 Project Structure
```
malicious-url-detector/
├── train_model.py           # Model training
├── malicious-url-detector/  # Flask backend
├── chrome-extension/        # Browser extension
├── templates/               # Web interface
└── tests/                   # Test suite (if added)
```

## ❓ Questions?

- Create a Discussion on GitHub
- Open an issue with `[QUESTION]` label
- Check existing documentation

## 🎉 Thank You!

Your contributions help make this project better for everyone!

---

**Happy Contributing! 🚀**
