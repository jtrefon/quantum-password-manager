#!/bin/bash

# Release script for Password Manager
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if we're in a git repository
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    print_error "Not in a git repository"
    exit 1
fi

# Check if working directory is clean
if ! git diff-index --quiet HEAD --; then
    print_error "Working directory is not clean. Please commit or stash changes."
    exit 1
fi

# Get current version from Cargo.toml
CURRENT_VERSION=$(grep '^version = ' Cargo.toml | cut -d'"' -f2)
print_status "Current version: $CURRENT_VERSION"

# Get new version from command line argument
if [ $# -eq 0 ]; then
    print_error "Usage: $0 <new_version>"
    print_error "Example: $0 1.0.0"
    exit 1
fi

NEW_VERSION=$1

# Validate version format (semantic versioning)
if ! [[ $NEW_VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.-]+)?(\+[a-zA-Z0-9.-]+)?$ ]]; then
    print_error "Invalid version format. Use semantic versioning (e.g., 1.0.0)"
    exit 1
fi

print_status "Preparing release $NEW_VERSION"

# Update version in Cargo.toml with cross-platform support
case "$(uname)" in
  Darwin*)
    sed -i '' "s/^version = \"$CURRENT_VERSION\"/version = \"$NEW_VERSION\"/" Cargo.toml
    ;;
  *)
    sed -i "s/^version = \"$CURRENT_VERSION\"/version = \"$NEW_VERSION\"/" Cargo.toml
    ;;
esac
print_status "Updated Cargo.toml version to $NEW_VERSION"

# Run tests
print_status "Running tests..."
cargo test --all-features
print_status "Tests passed"

# Run security audit
print_status "Running security audit..."
cargo audit
print_status "Security audit passed"

# Build release
print_status "Building release..."
cargo build --release
print_status "Release build completed"

# Create git tag
print_status "Creating git tag v$NEW_VERSION..."
git add Cargo.toml
git commit -m "chore: bump version to $NEW_VERSION"
git tag -a "v$NEW_VERSION" -m "Release version $NEW_VERSION"

# Push changes and tag
print_status "Pushing changes and tag..."
git push origin main
git push origin "v$NEW_VERSION"

print_status "Release $NEW_VERSION prepared successfully!"
print_status "GitHub Actions will now build and create a release automatically."

# Optional: Build Docker image
read -p "Do you want to build and push Docker image? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    print_status "Building Docker image..."
    docker build -t password-manager:$NEW_VERSION .
    docker tag password-manager:$NEW_VERSION password-manager:latest
    
    print_status "Docker image built successfully!"
    print_warning "Remember to push to your registry:"
    echo "  docker tag password-manager:$NEW_VERSION your-registry/password-manager:$NEW_VERSION"
    echo "  docker push your-registry/password-manager:$NEW_VERSION"
fi

print_status "Release process completed!" 
