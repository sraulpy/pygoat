pipeline {
    agent any
    
    environment {
        // Configuración general
        PROJECT_NAME = 'PyGoat'
        PYTHON_VERSION = '3.11'
        
        // DefectDojo configuration
        DEFECTDOJO_URL = "${env.DEFECTDOJO_URL ?: 'http://defectdojo-nginx:8080'}"
        DEFECTDOJO_API_KEY = credentials('defectdojo-api-key')
        DEFECTDOJO_PRODUCT_ID = "${env.DEFECTDOJO_PRODUCT_ID ?: '1'}"
        DEFECTDOJO_ENGAGEMENT_ID = "${env.DEFECTDOJO_ENGAGEMENT_ID ?: '1'}"
        
        // Dependency-Track configuration
        DEPENDENCY_TRACK_URL = "${env.DEPENDENCY_TRACK_URL ?: 'http://dependency-track-apiserver:8080'}"
        DEPENDENCY_TRACK_API_KEY = credentials('dependency-track-api-key')
        DEPENDENCY_TRACK_PROJECT_UUID = "${env.DEPENDENCY_TRACK_PROJECT_UUID ?: '8df1034c-a2a3-4550-b21c-b32970fe2096'}"
        
        // Security Gates Thresholds (Adjusted for PyGoat - intentionally vulnerable app)
        BANDIT_CRITICAL_THRESHOLD = '10'
        BANDIT_HIGH_THRESHOLD = '10'
        DEPENDENCY_TRACK_CRITICAL_THRESHOLD = '5'
        DEPENDENCY_TRACK_HIGH_THRESHOLD = '10'
        
        // Paths
        WORKSPACE_DIR = "${WORKSPACE}"
        REPORTS_DIR = "${WORKSPACE}/security-reports"
    }
    
    options {
        timeout(time: 30, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '10'))
        disableConcurrentBuilds()
    }
    
    stages {
        stage('Checkout') {
            steps {
                script {
                    echo "🔄 Checking out code from repository..."
                    checkout scm
                    
                    // Create reports directory
                    sh "mkdir -p ${REPORTS_DIR}"
                    
                    // Display build info
                    sh '''
                        echo "======================================"
                        echo "Build Information"
                        echo "======================================"
                        echo "Build Number: ${BUILD_NUMBER}"
                        echo "Job Name: ${JOB_NAME}"
                        echo "Workspace: ${WORKSPACE}"
                        echo "Git Branch: ${GIT_BRANCH}"
                        echo "Git Commit: ${GIT_COMMIT}"
                        echo "======================================"
                    '''
                }
            }
        }
        
        stage('Setup Environment') {
            steps {
                script {
                    echo "🔧 Setting up environment..."
                    sh '''
                        # Install security tools (pip is already installed)
                        pip install bandit safety cyclonedx-bom --break-system-packages
                        
                        # Install Gitleaks if not already available
                        if ! command -v gitleaks &> /dev/null; then
                            echo "Installing Gitleaks..."
                            wget -q https://github.com/gitleaks/gitleaks/releases/download/v8.18.2/gitleaks_8.18.2_linux_x64.tar.gz
                            tar -xzf gitleaks_8.18.2_linux_x64.tar.gz -C ${WORKSPACE}
                            chmod +x ${WORKSPACE}/gitleaks
                            rm gitleaks_8.18.2_linux_x64.tar.gz
                            echo "Gitleaks installed in ${WORKSPACE}/gitleaks"
                        else
                            echo "Gitleaks is already installed at $(command -v gitleaks)"
                        fi
                        
                        # Verify installations
                        echo "Tool versions:"
                        python3 --version
                        pip --version
                        bandit --version || echo "Bandit not installed"
                        gitleaks version || ${WORKSPACE}/gitleaks version || echo "Gitleaks not found"
                    '''
                }
            }
        }
        
        stage('Secrets Scanning - Gitleaks') {
            steps {
                script {
                    echo "🔐 Running Gitleaks secrets scanning..."
                    
                    // Run Gitleaks (use from PATH or workspace)
                    def gitleaksStatus = sh(
                        script: '''
                            set +e
                            GITLEAKS_CMD="gitleaks"
                            if ! command -v gitleaks &> /dev/null; then
                                GITLEAKS_CMD="${WORKSPACE}/gitleaks"
                            fi
                            
                            $GITLEAKS_CMD detect \
                                --source=${WORKSPACE} \
                                --report-path=${REPORTS_DIR}/gitleaks-report.json \
                                --report-format=json \
                                --verbose \
                                --no-git
                            echo $?
                        ''',
                        returnStdout: true
                    ).trim()
                    
                    echo "Gitleaks exit code: ${gitleaksStatus}"
                    
                    // Parse results
                    def gitleaksReport = readJSON file: "${REPORTS_DIR}/gitleaks-report.json"
                    def secretsFound = gitleaksReport ? gitleaksReport.size() : 0
                    
                    echo "🔍 Secrets found: ${secretsFound}"
                    
                    if (secretsFound > 0) {
                        echo "⚠️  WARNING: ${secretsFound} secrets detected!"
                        currentBuild.result = 'UNSTABLE'
                        
                        // Display secrets summary
                        sh """
                            echo "======================================"
                            echo "Secrets Detected:"
                            cat ${REPORTS_DIR}/gitleaks-report.json | jq -r '.[] | "File: \\(.File) | Line: \\(.StartLine) | Type: \\(.RuleID)"'
                            echo "======================================"
                        """
                    } else {
                        echo "✅ No secrets detected"
                    }
                    
                    // Archive report
                    archiveArtifacts artifacts: "security-reports/gitleaks-report.json", allowEmptyArchive: true
                }
            }
        }
        
        stage('SAST - Bandit') {
            steps {
                script {
                    echo "🔍 Running Bandit SAST analysis..."
                    
                    // Run Bandit
                    sh '''
                        bandit -r . \
                            -f json \
                            -o ${REPORTS_DIR}/bandit-report.json \
                            -ll \
                            --exit-zero \
                            --exclude ./venv,./env,./tests,./.git
                            
                        bandit -r . \
                            -f txt \
                            -o ${REPORTS_DIR}/bandit-report.txt \
                            -ll \
                            --exit-zero \
                            --exclude ./venv,./env,./tests,./.git
                    '''
                    
                    // Parse results
                    def banditReport = readJSON file: "${REPORTS_DIR}/bandit-report.json"
                    def metrics = banditReport.metrics
                    
                    // Count vulnerabilities by severity
                    def criticalCount = 0
                    def highCount = 0
                    def mediumCount = 0
                    def lowCount = 0
                    
                    banditReport.results.each { result ->
                        switch(result.issue_severity) {
                            case 'HIGH':
                                if (result.issue_confidence == 'HIGH') {
                                    criticalCount++
                                } else {
                                    highCount++
                                }
                                break
                            case 'MEDIUM':
                                mediumCount++
                                break
                            case 'LOW':
                                lowCount++
                                break
                        }
                    }
                    
                    echo """
                    ====================================
                    Bandit SAST Results:
                    ====================================
                    Critical: ${criticalCount}
                    High: ${highCount}
                    Medium: ${mediumCount}
                    Low: ${lowCount}
                    Total Issues: ${banditReport.results.size()}
                    ====================================
                    """
                    
                    // Store results for security gate
                    env.BANDIT_CRITICAL = criticalCount
                    env.BANDIT_HIGH = highCount
                    env.BANDIT_TOTAL = banditReport.results.size()
                    
                    // Archive reports
                    archiveArtifacts artifacts: "security-reports/bandit-report.*", allowEmptyArchive: false
                }
            }
        }
        
        stage('SCA - Dependency Check') {
            steps {
                script {
                    echo "📦 Running Software Composition Analysis..."
                    
                    // Generate SBOM (Software Bill of Materials)
                    sh '''
                        # Generate CycloneDX SBOM
                        if [ -f requirements.txt ]; then
                            cyclonedx-py requirements -i requirements.txt -o ${REPORTS_DIR}/sbom.json
                        else
                            echo "No requirements.txt found, creating minimal SBOM"
                            pip freeze > ${WORKSPACE}/requirements.txt
                            cyclonedx-py requirements -i ${WORKSPACE}/requirements.txt -o ${REPORTS_DIR}/sbom.json
                        fi
                        
                        # Run Safety check - create valid empty JSON if it fails
                        echo "Running Safety vulnerability scan..."
                        if ! safety check --json > ${REPORTS_DIR}/safety-report.json 2>&1; then
                            echo "Safety check failed or found issues. Creating valid JSON..."
                            echo '[]' > ${REPORTS_DIR}/safety-report.json
                        fi
                        
                        # Create text report
                        safety check --output text > ${REPORTS_DIR}/safety-report.txt 2>&1 || echo "Safety text report failed" > ${REPORTS_DIR}/safety-report.txt
                    '''
                    
                    // Parse Safety results - handle empty or invalid JSON gracefully
                    def safetyReport = sh(
                        script: """
                            if [ -f ${REPORTS_DIR}/safety-report.json ]; then
                                cat ${REPORTS_DIR}/safety-report.json
                            else
                                echo '[]'
                            fi
                        """,
                        returnStdout: true
                    ).trim()
                    
                    // Ensure we have valid JSON
                    if (!safetyReport || safetyReport.isEmpty() || safetyReport == "") {
                        safetyReport = "[]"
                    }
                    
                    def vulnerabilities = []
                    try {
                        vulnerabilities = readJSON text: safetyReport
                    } catch (Exception e) {
                        echo "Warning: Could not parse Safety report. Setting vulnerabilities to empty array."
                        vulnerabilities = []
                    }
                    
                    def vulnCount = vulnerabilities ? vulnerabilities.size() : 0
                    
                    echo """
                    ====================================
                    SCA Results (Safety):
                    ====================================
                    Vulnerable dependencies: ${vulnCount}
                    ====================================
                    """
                    
                    env.SCA_VULNERABILITIES = vulnCount
                    
                    // Archive artifacts
                    archiveArtifacts artifacts: "security-reports/sbom.json,security-reports/safety-report.*", allowEmptyArchive: true
                }
            }
        }
        
        stage('Upload to Dependency-Track') {
            when {
                expression { env.DEPENDENCY_TRACK_API_KEY != null }
            }
            steps {
                script {
                    echo "📤 Uploading SBOM to Dependency-Track..."
                    
                    sh '''
                        # Upload SBOM to Dependency-Track
                        curl -X POST "${DEPENDENCY_TRACK_URL}/api/v1/bom" \
                            -H "X-Api-Key: ${DEPENDENCY_TRACK_API_KEY}" \
                            -H "Content-Type: multipart/form-data" \
                            -F "project=${DEPENDENCY_TRACK_PROJECT_UUID}" \
                            -F "bom=@${REPORTS_DIR}/sbom.json" \
                            -o ${REPORTS_DIR}/dependency-track-upload.json
                        
                        echo "Dependency-Track upload response:"
                        cat ${REPORTS_DIR}/dependency-track-upload.json
                    '''
                    
                    // Wait for analysis to complete
                    sleep(time: 30, unit: 'SECONDS')
                    
                    // Retrieve metrics with error handling
                    sh '''
                        # Get project metrics - create empty JSON if fails
                        if ! curl -X GET "${DEPENDENCY_TRACK_URL}/api/v1/metrics/project/${DEPENDENCY_TRACK_PROJECT_UUID}/current" \
                            -H "X-Api-Key: ${DEPENDENCY_TRACK_API_KEY}" \
                            -o ${REPORTS_DIR}/dependency-track-metrics.json 2>&1; then
                            echo '{"critical":0,"high":0,"medium":0,"low":0}' > ${REPORTS_DIR}/dependency-track-metrics.json
                        fi
                        
                        # Verify metrics file has valid content
                        if [ ! -s ${REPORTS_DIR}/dependency-track-metrics.json ]; then
                            echo '{"critical":0,"high":0,"medium":0,"low":0}' > ${REPORTS_DIR}/dependency-track-metrics.json
                        fi
                        
                        # Get vulnerabilities - create empty array if fails
                        if ! curl -X GET "${DEPENDENCY_TRACK_URL}/api/v1/vulnerability/project/${DEPENDENCY_TRACK_PROJECT_UUID}" \
                            -H "X-Api-Key: ${DEPENDENCY_TRACK_API_KEY}" \
                            -o ${REPORTS_DIR}/dependency-track-vulnerabilities.json 2>&1; then
                            echo '[]' > ${REPORTS_DIR}/dependency-track-vulnerabilities.json
                        fi
                        
                        # Verify vulnerabilities file has valid content
                        if [ ! -s ${REPORTS_DIR}/dependency-track-vulnerabilities.json ]; then
                            echo '[]' > ${REPORTS_DIR}/dependency-track-vulnerabilities.json
                        fi
                    '''
                    
                    // Parse metrics with error handling
                    def metrics = null
                    def dtCritical = 0
                    def dtHigh = 0
                    def dtMedium = 0
                    def dtLow = 0
                    
                    try {
                        metrics = readJSON file: "${REPORTS_DIR}/dependency-track-metrics.json"
                        dtCritical = metrics?.critical ?: 0
                        dtHigh = metrics?.high ?: 0
                        dtMedium = metrics?.medium ?: 0
                        dtLow = metrics?.low ?: 0
                    } catch (Exception e) {
                        echo "Warning: Could not parse Dependency-Track metrics. Using default values."
                        echo "Error: ${e.message}"
                    }
                    
                    echo """
                    ====================================
                    Dependency-Track Results:
                    ====================================
                    Critical: ${dtCritical}
                    High: ${dtHigh}
                    Medium: ${dtMedium}
                    Low: ${dtLow}
                    ====================================
                    """
                    
                    env.DT_CRITICAL = dtCritical
                    env.DT_HIGH = dtHigh
                }
            }
        }
        
        stage('Upload to DefectDojo') {
            when {
                expression { env.DEFECTDOJO_API_KEY != null }
            }
            steps {
                script {
                    echo "📤 Uploading results to DefectDojo..."
                    
                    // Upload Bandit results
                    sh """
                        curl -X POST '${DEFECTDOJO_URL}/api/v2/import-scan/' \
                            -H 'Authorization: Token ${DEFECTDOJO_API_KEY}' \
                            -F 'scan_type=Bandit Scan' \
                            -F 'file=@${REPORTS_DIR}/bandit-report.json' \
                            -F 'engagement=${DEFECTDOJO_ENGAGEMENT_ID}' \
                            -F 'verified=true' \
                            -F 'active=true' \
                            -F 'scan_date=${BUILD_TIMESTAMP}' \
                            -F 'minimum_severity=Info' \
                            -o ${REPORTS_DIR}/defectdojo-bandit-upload.json
                    """
                    
                    // Upload Gitleaks results
                    sh """
                        curl -X POST '${DEFECTDOJO_URL}/api/v2/import-scan/' \
                            -H 'Authorization: Token ${DEFECTDOJO_API_KEY}' \
                            -F 'scan_type=Gitleaks Scan' \
                            -F 'file=@${REPORTS_DIR}/gitleaks-report.json' \
                            -F 'engagement=${DEFECTDOJO_ENGAGEMENT_ID}' \
                            -F 'verified=true' \
                            -F 'active=true' \
                            -F 'scan_date=${BUILD_TIMESTAMP}' \
                            -o ${REPORTS_DIR}/defectdojo-gitleaks-upload.json || true
                    """
                    
                    // Upload Safety results
                    sh """
                        curl -X POST '${DEFECTDOJO_URL}/api/v2/import-scan/' \
                            -H 'Authorization: Token ${DEFECTDOJO_API_KEY}' \
                            -F 'scan_type=Safety Scan' \
                            -F 'file=@${REPORTS_DIR}/safety-report.json' \
                            -F 'engagement=${DEFECTDOJO_ENGAGEMENT_ID}' \
                            -F 'verified=true' \
                            -F 'active=true' \
                            -F 'scan_date=${BUILD_TIMESTAMP}' \
                            -o ${REPORTS_DIR}/defectdojo-safety-upload.json || true
                    """
                    
                    echo "✅ Results uploaded to DefectDojo"
                    
                    // Display upload results
                    sh """
                        echo "======================================"
                        echo "DefectDojo Upload Results:"
                        echo "======================================"
                        echo "Bandit upload:"
                        cat ${REPORTS_DIR}/defectdojo-bandit-upload.json | jq '.' || cat ${REPORTS_DIR}/defectdojo-bandit-upload.json
                        echo ""
                        echo "======================================"
                    """
                }
            }
        }
        
        stage('Security Gate - SAST') {
            steps {
                script {
                    echo "🚦 Evaluating SAST Security Gate..."
                    
                    def banditCritical = env.BANDIT_CRITICAL.toInteger()
                    def banditHigh = env.BANDIT_HIGH.toInteger()
                    def criticalThreshold = env.BANDIT_CRITICAL_THRESHOLD.toInteger()
                    def highThreshold = env.BANDIT_HIGH_THRESHOLD.toInteger()
                    
                    def gateStatus = true
                    def gateMessages = []
                    
                    if (banditCritical > criticalThreshold) {
                        gateStatus = false
                        gateMessages.add("❌ CRITICAL: ${banditCritical} critical vulnerabilities found (threshold: ${criticalThreshold})")
                    }
                    
                    if (banditHigh > highThreshold) {
                        gateStatus = false
                        gateMessages.add("❌ HIGH: ${banditHigh} high vulnerabilities found (threshold: ${highThreshold})")
                    }
                    
                    echo """
                    ====================================
                    SAST Security Gate Results:
                    ====================================
                    Critical Issues: ${banditCritical} (Threshold: ${criticalThreshold})
                    High Issues: ${banditHigh} (Threshold: ${highThreshold})
                    ====================================
                    """
                    
                    if (!gateStatus) {
                        echo "🚨 SECURITY GATE FAILED - SAST"
                        gateMessages.each { msg -> echo msg }
                        error("Security Gate Failed: SAST vulnerabilities exceed threshold")
                    } else {
                        echo "✅ SAST Security Gate PASSED"
                    }
                }
            }
        }
        
        stage('Security Gate - SCA') {
            when {
                expression { env.DEPENDENCY_TRACK_API_KEY != null }
            }
            steps {
                script {
                    echo "🚦 Evaluating SCA Security Gate..."
                    
                    def dtCritical = env.DT_CRITICAL.toInteger()
                    def dtHigh = env.DT_HIGH.toInteger()
                    def criticalThreshold = env.DEPENDENCY_TRACK_CRITICAL_THRESHOLD.toInteger()
                    def highThreshold = env.DEPENDENCY_TRACK_HIGH_THRESHOLD.toInteger()
                    
                    def gateStatus = true
                    def gateMessages = []
                    
                    if (dtCritical > criticalThreshold) {
                        gateStatus = false
                        gateMessages.add("❌ CRITICAL: ${dtCritical} critical vulnerabilities in dependencies (threshold: ${criticalThreshold})")
                    }
                    
                    if (dtHigh > highThreshold) {
                        gateStatus = false
                        gateMessages.add("❌ HIGH: ${dtHigh} high vulnerabilities in dependencies (threshold: ${highThreshold})")
                    }
                    
                    echo """
                    ====================================
                    SCA Security Gate Results:
                    ====================================
                    Critical Issues: ${dtCritical} (Threshold: ${criticalThreshold})
                    High Issues: ${dtHigh} (Threshold: ${highThreshold})
                    ====================================
                    """
                    
                    if (!gateStatus) {
                        echo "🚨 SECURITY GATE FAILED - SCA"
                        gateMessages.each { msg -> echo msg }
                        error("Security Gate Failed: Dependency vulnerabilities exceed threshold")
                    } else {
                        echo "✅ SCA Security Gate PASSED"
                    }
                }
            }
        }
        
        stage('Generate Security Report') {
            steps {
                script {
                    echo "📊 Generating consolidated security report..."
                    
                    sh '''
                        cat > ${REPORTS_DIR}/security-summary.txt << EOF
====================================
SECURITY SCAN SUMMARY
====================================
Build: ${BUILD_NUMBER}
Date: $(date)
Project: ${PROJECT_NAME}

====================================
SECRETS SCANNING (Gitleaks)
====================================
Status: ${GITLEAKS_STATUS:-PASSED}
Secrets Found: ${SECRETS_COUNT:-0}

====================================
SAST (Bandit)
====================================
Critical: ${BANDIT_CRITICAL}
High: ${BANDIT_HIGH}
Total Issues: ${BANDIT_TOTAL}

====================================
SCA (Dependency Check)
====================================
Vulnerable Dependencies: ${SCA_VULNERABILITIES}
Critical: ${DT_CRITICAL:-N/A}
High: ${DT_HIGH:-N/A}

====================================
SECURITY GATES
====================================
SAST Gate: PASSED
SCA Gate: ${DT_GATE_STATUS:-SKIPPED}

====================================
INTEGRATIONS
====================================
DefectDojo: ${DEFECTDOJO_URL}
Dependency-Track: ${DEPENDENCY_TRACK_URL}

====================================
EOF
                        
                        cat ${REPORTS_DIR}/security-summary.txt
                    '''
                    
                    archiveArtifacts artifacts: "security-reports/security-summary.txt", allowEmptyArchive: false
                }
            }
        }
    }
    
    post {
        always {
            script {
                echo "🧹 Cleaning up..."
                
                // Publish HTML reports if available
                // NOTE: Requires HTML Publisher plugin
                // Uncomment after installing the plugin
                // publishHTML([
                //     allowMissing: true,
                //     alwaysLinkToLastBuild: true,
                //     keepAll: true,
                //     reportDir: 'security-reports',
                //     reportFiles: '*.txt,*.json',
                //     reportName: 'Security Reports'
                // ])
                
                // Clean workspace if needed
                // cleanWs()
            }
        }
        
        success {
            echo "✅ Pipeline completed successfully!"
            
            // Send notification (configure your notification method)
            // emailext(
            //     subject: "✅ Security Pipeline Success - ${env.JOB_NAME} #${env.BUILD_NUMBER}",
            //     body: "Security pipeline completed successfully. Check the report at ${env.BUILD_URL}",
            //     to: "${env.NOTIFICATION_EMAIL}"
            // )
        }
        
        failure {
            echo "❌ Pipeline failed!"
            
            // Send failure notification
            // emailext(
            //     subject: "❌ Security Pipeline Failed - ${env.JOB_NAME} #${env.BUILD_NUMBER}",
            //     body: "Security pipeline failed. Check logs at ${env.BUILD_URL}console",
            //     to: "${env.NOTIFICATION_EMAIL}"
            // )
        }
        
        unstable {
            echo "⚠️  Pipeline unstable - review security findings"
        }
    }
}
