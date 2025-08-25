#!/bin/bash

# InfoBlox Audit Tool Setup Script
# This script sets up the development and runtime environment

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        log_warning "This script should not be run as root for security reasons"
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# Check system requirements
check_requirements() {
    log_info "Checking system requirements..."
    
    # Check Python version
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
        PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d'.' -f1)
        PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d'.' -f2)
        
        if [[ $PYTHON_MAJOR -eq 3 && $PYTHON_MINOR -ge 8 ]]; then
            log_success "Python $PYTHON_VERSION found"
        else
            log_error "Python 3.8+ required, found $PYTHON_VERSION"
            exit 1
        fi
    else
        log_error "Python 3 not found. Please install Python 3.8+"
        exit 1
    fi
    
    # Check pip
    if ! command -v pip3 &> /dev/null; then
        log_error "pip3 not found. Please install pip3"
        exit 1
    fi
    
    # Check git
    if ! command -v git &> /dev/null; then
        log_warning "Git not found. Some features may not work properly"
    fi
    
    # Check Docker (optional)
    if command -v docker &> /dev/null; then
        log_success "Docker found"
        DOCKER_AVAILABLE=true
    else
        log_warning "Docker not found. Docker features will be unavailable"
        DOCKER_AVAILABLE=false
    fi
}

# Create virtual environment
setup_venv() {
    log_info "Setting up Python virtual environment..."
    
    if [[ ! -d "venv" ]]; then
        python3 -m venv venv
        log_success "Virtual environment created"
    else
        log_info "Virtual environment already exists"
    fi
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip
    log_success "pip upgraded"
}

# Install Python dependencies
install_dependencies() {
    log_info "Installing Python dependencies..."
    
    if [[ -f "requirements.txt" ]]; then
        pip install -r requirements.txt
        log_success "Dependencies installed"
    else
        log_error "requirements.txt not found"
        exit 1
    fi
}

# Create necessary directories
create_directories() {
    log_info "Creating necessary directories..."
    
    directories=("logs" "reports" "config/backup" "data")
    
    for dir in "${directories[@]}"; do
        if [[ ! -d "$dir" ]]; then
            mkdir -p "$dir"
            log_info "Created directory: $dir"
        fi
    done
    
    log_success "Directories created"
}

# Set up configuration
setup_config() {
    log_info "Setting up configuration..."
    
    # Create environment file template
    if [[ ! -f ".env" ]]; then
        cat > .env << EOF
# InfoBlox Audit Tool Environment Variables
# Copy this file and customize for your environment

# InfoBlox Connection
INFOBLOX_HOST=
INFOBLOX_USERNAME=admin
INFOBLOX_PASSWORD=
INFOBLOX_PORT=443
INFOBLOX_SSL_VERIFY=true

# Logging
LOG_LEVEL=INFO
LOG_FILE=logs/audit.log

# Report Settings
REPORT_OUTPUT_DIR=reports
DEFAULT_REPORT_FORMAT=html

# Security Settings
AUDIT_TIMEOUT=300
MAX_CONCURRENT_AUDITS=1
EOF
        log_success "Environment template created (.env)"
        log_warning "Please edit .env file with your InfoBlox credentials"
    else
        log_info "Environment file already exists"
    fi
    
    # Backup original config if it exists
    if [[ -f "config/config.yaml" ]]; then
        cp config/config.yaml config/backup/config.yaml.backup.$(date +%Y%m%d_%H%M%S)
        log_info "Backed up existing configuration"
    fi
}

# Set up Docker environment
setup_docker() {
    if [[ "$DOCKER_AVAILABLE" == true ]]; then
        log_info "Setting up Docker environment..."
        
        # Create Dockerfile if it doesn't exist
        if [[ ! -f "docker/Dockerfile" ]]; then
            cat > docker/Dockerfile << 'EOF'
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ ./src/
COPY config/ ./config/
COPY main.py .

# Create directories
RUN mkdir -p logs reports

# Set environment variables
ENV PYTHONPATH=/app/src
ENV LOG_LEVEL=INFO

# Expose port (if needed for web interface)
EXPOSE 8080

# Run the application
CMD ["python", "main.py", "--help"]
EOF
            log_success "Dockerfile created"
        fi
        
        # Create docker-compose.yml if it doesn't exist
        if [[ ! -f "docker/docker-compose.yml" ]]; then
            cat > docker/docker-compose.yml << 'EOF'
version: '3.8'

services:
  infoblox-audit:
    build:
      context: ..
      dockerfile: docker/Dockerfile
    container_name: infoblox-audit
    volumes:
      - ../logs:/app/logs
      - ../reports:/app/reports
      - ../config:/app/config
    environment:
      - PYTHONPATH=/app/src
      - LOG_LEVEL=${LOG_LEVEL:-INFO}
    networks:
      - audit-network
    restart: unless-stopped

networks:
  audit-network:
    driver: bridge
EOF
            log_success "docker-compose.yml created"
        fi
        
        # Create .dockerignore
        if [[ ! -f ".dockerignore" ]]; then
            cat > .dockerignore << 'EOF'
.git
.gitignore
README.md
.env
venv/
__pycache__/
*.pyc
*.pyo
*.pyd
.pytest_cache/
.coverage
htmlcov/
.tox/
.cache
nosetests.xml
coverage.xml
*.cover
.hypothesis/
.DS_Store
EOF
            log_success ".dockerignore created"
        fi
    fi
}

# Run tests
run_tests() {
    log_info "Running tests..."
    
    if command -v pytest &> /dev/null; then
        # Run tests with coverage
        pytest tests/ -v --cov=src --cov-report=html --cov-report=term
        
        if [[ $? -eq 0 ]]; then
            log_success "All tests passed"
        else
            log_warning "Some tests failed. Check the output above."
        fi
    else
        log_warning "pytest not found. Installing..."
        pip install pytest pytest-cov
        pytest tests/ -v --cov=src --cov-report=html --cov-report=term
    fi
}

# Set up pre-commit hooks
setup_hooks() {
    log_info "Setting up development hooks..."
    
    # Create pre-commit hook
    if [[ -d ".git" ]]; then
        cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
# Pre-commit hook for InfoBlox Audit Tool

echo "Running pre-commit checks..."

# Run linting
echo "Running flake8..."
flake8 src/ tests/ --max-line-length=100 --ignore=E203,W503

if [[ $? -ne 0 ]]; then
    echo "Linting failed. Please fix the issues above."
    exit 1
fi

# Run tests
echo "Running tests..."
pytest tests/ -q

if [[ $? -ne 0 ]]; then
    echo "Tests failed. Please fix the issues above."
    exit 1
fi

echo "Pre-commit checks passed!"
EOF
        chmod +x .git/hooks/pre-commit
        log_success "Pre-commit hook installed"
    fi
}

# Create run script
create_run_script() {
    log_info "Creating run script..."
    
    cat > run.sh << 'EOF'
#!/bin/bash
# InfoBlox Audit Tool Runner Script

# Activate virtual environment if it exists
if [[ -f "venv/bin/activate" ]]; then
    source venv/bin/activate
fi

# Load environment variables
if [[ -f ".env" ]]; then
    export $(grep -v '^#' .env | xargs)
fi

# Run the audit tool
python main.py "$@"
EOF
    
    chmod +x run.sh
    log_success "Run script created (run.sh)"
}

# Main setup function
main() {
    echo "=================================================="
    echo "InfoBlox Audit Tool Setup"
    echo "=================================================="
    
    check_root
    check_requirements
    setup_venv
    install_dependencies
    create_directories
    setup_config
    setup_docker
    create_run_script
    setup_hooks
    
    log_info "Running initial tests..."
    run_tests
    
    echo "=================================================="
    log_success "Setup completed successfully!"
    echo "=================================================="
    
    echo ""
    echo "Next steps:"
    echo "1. Edit .env file with your InfoBlox credentials"
    echo "2. Review config/config.yaml for audit settings"
    echo "3. Run the tool: ./run.sh --target <infoblox-ip>"
    echo ""
    echo "For Docker usage:"
    echo "1. cd docker"
    echo "2. docker-compose up --build"
    echo ""
    echo "For development:"
    echo "1. source venv/bin/activate"
    echo "2. python main.py --help"
    echo ""
}

# Run main function
main "$@"
