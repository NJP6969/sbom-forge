import pytest
from pathlib import Path


@pytest.fixture
def sample_package_lock_json(tmp_path: Path) -> Path:
    lock_file = tmp_path / "package-lock.json"
    content = """{
  "name": "sample-project",
  "version": "1.0.0",
  "lockfileVersion": 2,
  "requires": true,
  "packages": {
    "": {
      "name": "sample-project",
      "version": "1.0.0",
      "dependencies": {
        "express": "^4.18.2"
      },
      "devDependencies": {
        "jest": "^29.5.0"
      }
    },
    "node_modules/express": {
      "version": "4.18.2",
      "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
      "integrity": "sha512-5/PsL6iGPdfQ/lKM1UuielYgv3BUaGEqx3v1ALJw1iL+qpGv7JU1gL51wGv55w84y71GkcBUjQ25n6bVdw==",
      "dependencies": {
        "body-parser": "1.20.1",
        "qs": "6.11.0"
      }
    },
    "node_modules/body-parser": {
      "version": "1.20.1",
      "resolved": "https://registry.npmjs.org/body-parser/-/body-parser-1.20.1.tgz",
      "integrity": "sha512-jWi7abTbYzsKbXfJHyBN5xiqhvy4gfp41ewu7ZHEID3v38P7cuhUhiHcdcvUvhAGca51v4cI6l1vwY/UKdYL7Q=="
    },
    "node_modules/qs": {
      "version": "6.11.0",
      "resolved": "https://registry.npmjs.org/qs/-/qs-6.11.0.tgz",
      "integrity": "sha512-MvjoMCJwEarSbUYk5U+LTHErhtaccZN5Clyrcg8V/jpxSC5yh5t455mSlCI6h5FhkbJu18yv022dvuHYVq+WvQ=="
    },
    "node_modules/jest": {
      "version": "29.5.0",
      "dev": true
    }
  }
}"""
    lock_file.write_text(content, encoding="utf-8")
    return lock_file


@pytest.fixture
def sample_requirements_txt(tmp_path: Path) -> Path:
    req_file = tmp_path / "requirements.txt"
    content = """# Sample requirements
flask==2.3.2
requests==2.31.0 --hash=sha256:455708e03...
pytest>=7.4.0
"""
    req_file.write_text(content, encoding="utf-8")
    return req_file
