pipeline {
    agent any
    
    environment {
        // Configuración general
        PROJECT_NAME = 'PyGoat'
        PYTHON_VERSION = '3.11'
        
        // DefectDojo configuration
        DEFECTDOJO_URL = "${env.DEFECTDOJO_URL ?: 'http://defectdojo:8080'}"
        DEFECTDOJO_API_KEY = credentials('ed53ff69ee3424b81a0c6b775a2a5cd6094afeaa')
        DEFECTDOJO_PRODUCT_ID = "${env.DEFECTDOJO_PRODUCT_ID ?: '1'}"
        DEFECTDOJO_ENGAGEMENT_ID = "${env.DEFECTDOJO_ENGAGEMENT_ID ?: '1'}"
        
        // Dependency-Track configuration
        DEPENDENCY_TRACK_URL = "${env.DEPENDENCY_TRACK_URL ?: 'http://dependency-track:8081'}"
        DEPENDENCY_TRACK_API_KEY = credentials('odt_fBiewS5A_FQg7qHjRKpQDIbLPbvtAero8EAqGm6uB')
        DEPENDENCY_TRACK_PROJECT_UUID = "${env.DEPENDENCY_TRACK_PROJECT_UUID ?: '8df1034c-a2a3-4550-b21c-b32970fe2096'}"
        
        // Security Gates Thresholds
        BANDIT_CRITICAL_THRESHOLD = '0'
        BANDIT_HIGH_THRESHOLD = '5'
        DEPENDENCY_TRACK_CRITICAL_THRESHOLD = '0'
        DEPENDENCY_TRACK_HIGH_THRESHOLD = '3'
        
        // Paths
        WORKSPACE_DIR = "${WORKSPACE}"
        REPORTS_DIR = "${WORKSPACE}/security-reports"
    }
    
    options {
        timestamps()
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
                        # Install Python dependencies
                        python3 -m pip install --upgrade pip
                        
                        # Install security tools
                        pip install bandit safety cyclonedx-bom
                        
                        # Install Gitleaks (if not already installed)
                        if ! command -v gitleaks &> /dev/null; then
                            echo "Installing Gitleaks..."
                            wget -q https://github.com/gitleaks/gitleaks/releases/download/v8.18.2/gitleaks_8.18.2_linux_x64.tar.gz
                            tar -xzf gitleaks_8.18.2_linux_x64.tar.gz
                            chmod +x gitleaks
                            sudo mv gitleaks /usr/local/bin/ || mv gitleaks ${WORKSPACE}/
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
                    
                    // Run Gitleaks
                    def gitleaksStatus = sh(
                        script: '''
                            set +e
                            gitleaks detect \
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
                            cyclonedx-py -r -i requirements.txt -o ${REPORTS_DIR}/sbom.json
                        else
                            echo "No requirements.txt found, creating minimal SBOM"
                            pip freeze > ${WORKSPACE}/requirements.txt
                            cyclonedx-py -r -i ${WORKSPACE}/requirements.txt -o ${REPORTS_DIR}/sbom.json
                        fi
                        
                        # Run Safety check
                        safety check --json --output ${REPORTS_DIR}/safety-report.json || true
                        safety check --output ${REPORTS_DIR}/safety-report.txt || true
                    '''
                    
                    // Parse Safety results
                    def safetyReport = sh(
                        script: "cat ${REPORTS_DIR}/safety-report.json || echo '[]'",
                        returnStdout: true
                    ).trim()
                    
                    def vulnerabilities = readJSON text: safetyReport
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
                    
                    // Retrieve metrics
                    sh '''
                        # Get project metrics
                        curl -X GET "${DEPENDENCY_TRACK_URL}/api/v1/metrics/project/${DEPENDENCY_TRACK_PROJECT_UUID}/current" \
                            -H "X-Api-Key: ${DEPENDENCY_TRACK_API_KEY}" \
                            -o ${REPORTS_DIR}/dependency-track-metrics.json
                        
                        # Get vulnerabilities
                        curl -X GET "${DEPENDENCY_TRACK_URL}/api/v1/vulnerability/project/${DEPENDENCY_TRACK_PROJECT_UUID}" \
                            -H "X-Api-Key: ${DEPENDENCY_TRACK_API_KEY}" \
                            -o ${REPORTS_DIR}/dependency-track-vulnerabilities.json
                    '''
                    
                    // Parse metrics
                    def metrics = readJSON file: "${REPORTS_DIR}/dependency-track-metrics.json"
                    
                    def dtCritical = metrics?.critical ?: 0
                    def dtHigh = metrics?.high ?: 0
                    def dtMedium = metrics?.medium ?: 0
                    def dtLow = metrics?.low ?: 0
                    
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
                publishHTML([
                    allowMissing: true,
                    alwaysLinkToLastBuild: true,
                    keepAll: true,
                    reportDir: 'security-reports',
                    reportFiles: '*.txt,*.json',
                    reportName: 'Security Reports'
                ])
                
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
