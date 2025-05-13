#!/bin/bash

echo "Security Vulnerabilities Demo"
echo "==========================="
echo ""
echo "This script helps you run the vulnerable and secure applications."
echo ""

show_menu() {
    echo "Choose an option:"
    echo "1. Run vulnerable application"
    echo "2. Run secure application"
    echo "3. Run both applications using Docker Compose"
    echo "4. Run vulnerability tests against the vulnerable app"
    echo "5. Run vulnerability tests against the secure app"
    echo "6. Run all PoC exploits against the vulnerable app"
    echo "7. Exit"
    echo ""
    read -p "Enter your choice (1-7): " choice
}

run_vulnerable_app() {
    echo "Starting vulnerable application on http://localhost:5000"
    echo "Press Ctrl+C to stop"
    python vulnerable_app.py
}

run_secure_app() {
    echo "Starting secure application on http://localhost:5000"
    echo "Press Ctrl+C to stop"
    python secure_app.py
}

run_docker_compose() {
    echo "Starting both applications using Docker Compose"
    echo "Vulnerable app will be available at http://localhost:5000"
    echo "Secure app will be available at http://localhost:5001"
    echo "Press Ctrl+C to stop"
    docker-compose up --build
}

run_vulnerability_tests_vulnerable() {
    echo "Running vulnerability tests against the vulnerable app"
    python test_vulnerabilities.py http://localhost:5000
}

run_vulnerability_tests_secure() {
    echo "Running vulnerability tests against the secure app"
    python test_vulnerabilities.py http://localhost:5001
}

run_poc_exploits() {
    echo "Running all PoC exploits against the vulnerable app"
    python poc/run_all_pocs.py http://localhost:5000
}

while true; do
    show_menu
    
    case $choice in
        1) run_vulnerable_app; break ;;
        2) run_secure_app; break ;;
        3) run_docker_compose; break ;;
        4) run_vulnerability_tests_vulnerable; break ;;
        5) run_vulnerability_tests_secure; break ;;
        6) run_poc_exploits; break ;;
        7) echo "Exiting."; exit 0 ;;
        *) echo "Invalid option. Please try again." ;;
    esac
done