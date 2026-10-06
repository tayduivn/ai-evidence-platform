from setuptools import setup, find_packages

setup(
    name="ai-evidence-sdk",
    version="0.3.0",
    description="High-performance, resilient Python SDK for AI Evidence & Accountability Platform",
    long_description=open("README.md", encoding="utf-8").read() if __import__("os").path.exists("README.md") else "",
    long_description_content_type="text/markdown",
    packages=find_packages(include=["ai_evidence_sdk*"]),
    python_requires=">=3.9",
    install_requires=[],
    extras_require={
        "test": ["pytest>=7.0.0"],
    },
)
