// Form Functions for SonicWall Credential Reset Tool
// Handles form interactions, validation, connection testing, and analysis operations

// Helper functions for handling connection test results
function handleConnectionTestResult(result) {
    // Remove any existing connection result messages
    const existingResult = document.getElementById('connection-result');
    if (existingResult) {
        existingResult.remove();
    }

    // Create success message
    const resultDiv = document.createElement('div');
    resultDiv.id = 'connection-result';
    resultDiv.className = 'mt-4 p-4 bg-green-100 border border-green-400 text-green-700 rounded-md';

    let resultHTML = '<strong>✅ Connection Successful!</strong><br>';

    if (result.firewall_info) {
        const info = result.firewall_info;
        resultHTML += `
            <div class="mt-2 text-sm">
                <strong>Firewall Information:</strong><br>
                ${info.device_model ? `• Model: ${info.device_model}<br>` : ''}
                ${info.firmware_version ? `• Firmware: ${info.firmware_version}<br>` : ''}
                ${info.serial_number ? `• Serial: ${info.serial_number}<br>` : ''}
                ${info.firewall_generation ? `• Generation: ${info.firewall_generation}<br>` : ''}
            </div>
        `;

        // Add API status section if API was auto-enabled
        if (info.api_autoenabled) {
            resultHTML += `
                <div class="mt-3 p-2 bg-orange-50 border border-orange-200 rounded text-orange-800 text-sm">
                    <strong>API Status:</strong> SonicOS API was temporarily auto-enabled via SSH for this connection test and has been automatically disabled after completion.
                </div>
            `;
        }
    }

    resultDiv.innerHTML = resultHTML;

    // Insert after the form
    const form = document.getElementById('single-target-form');
    form.parentNode.insertBefore(resultDiv, form.nextSibling);

    console.log('Connection test successful:', result);
}

function handleConnectionTestError(errorMessage) {
    // Remove any existing connection result messages
    const existingResult = document.getElementById('connection-result');
    if (existingResult) {
        existingResult.remove();
    }

    // Create error message
    const resultDiv = document.createElement('div');
    resultDiv.id = 'connection-result';
    resultDiv.className = 'mt-4 p-4 bg-red-100 border border-red-400 text-red-700 rounded-md';
    resultDiv.innerHTML = `
        <strong>❌ Connection Failed</strong><br>
        <div class="mt-2 text-sm">${errorMessage}</div>
        <div class="mt-2 text-xs text-gray-600">
            Please verify your credentials and ensure the firewall is accessible.
        </div>
    `;

    // Insert after the form
    const form = document.getElementById('single-target-form');
    form.parentNode.insertBefore(resultDiv, form.nextSibling);

    console.error('Connection test failed:', errorMessage);
}

function handleAnalysisError(errorMessage) {
    console.error('Analysis error:', errorMessage);

    // Remove any existing analysis result messages
    const existingResult = document.getElementById('analysis-result');
    if (existingResult) {
        existingResult.remove();
    }

    // Create error message
    const resultDiv = document.createElement('div');
    resultDiv.id = 'analysis-result';
    resultDiv.className = 'mt-4 p-4 bg-red-100 border border-red-400 text-red-700 rounded-md';
    resultDiv.innerHTML = `
        <strong>❌ Analysis Failed</strong><br>
        <div class="mt-2 text-sm">${errorMessage}</div>
        <div class="mt-2 text-xs text-gray-600">
            Please verify your connection and try again.
        </div>
    `;

    // Insert after the form
    const form = document.getElementById('single-target-form');
    form.parentNode.insertBefore(resultDiv, form.nextSibling);

    // Show alert as well for immediate user feedback
    window.alert(`Analysis Failed: ${errorMessage}`);
}

// Reset form function
function resetSingleTargetForm() {
    // Clear all text inputs
    // TODO: Remove the test values before deployment
    document.getElementById('firewall-ip').value = '192.168.0.208';
    document.getElementById('ssh-port').value = '22';
    document.getElementById('admin-username').value = 'admin';
    document.getElementById('admin-password').value = 'password';
    document.getElementById('temp-password').value = '';

    // Reset checkboxes to unchecked
    document.getElementById('force-password-change').checked = false;
    document.getElementById('unbind-totp').checked = false;
    document.getElementById('export-settings').checked = false;
    document.getElementById('export-tsr').checked = false;

    // Reset radio buttons to default (random password)
    document.getElementById('random-password').checked = true;
    document.getElementById('custom-password').checked = false;

    // Disable temp password input (default state)
    document.getElementById('temp-password').disabled = true;

    // Reset security level dropdown to default (all levels)
    document.getElementById('security-level-select').value = 'all';

    // Clear any existing error messages
    const existingError = document.getElementById('form-errors');
    if (existingError) {
        existingError.remove();
    }

    // Clear any connection result messages
    const existingResult = document.getElementById('connection-result');
    if (existingResult) {
        existingResult.remove();
    }

    // Clear any validation feedback messages
    const feedbackElements = document.querySelectorAll('#password-feedback, #ip-feedback');
    feedbackElements.forEach(element => {
        element.remove();
    });

    console.log('Form reset to default values');
}

// New SSE-based connection test with real-time progress
async function testConnectionWithProgress(formData, testConnectionBtn) {
    testConnectionBtn.disabled = true;
    testConnectionBtn.innerHTML = '<span class="inline-flex items-center"><svg class="animate-spin -ml-1 mr-2 h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>Testing...</span>';

    showProgressModal(`Testing Connection to ${formData.firewall}`);
    updateProgress(0, 'Starting connection test...');

    try {
        // Start the connection test with progress tracking
        const response = await fetch('/test_connection_with_progress', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(formData)
        });

        const result = await response.json();

        if (response.ok && result.success && result.operation_id) {
            // Start SSE stream to get real-time progress
            const operationId = result.operation_id;
            console.log(`Starting SSE stream for operation ${operationId}`);

            const eventSource = new EventSource(`/progress/${operationId}`);

            eventSource.onmessage = function(event) {
                try {
                    const progressData = JSON.parse(event.data);
                    console.log('Progress update:', progressData);

                    if (progressData.type === 'progress') {
                        // Update progress bar and current step
                        if (progressData.percentage !== undefined) {
                            updateProgress(progressData.percentage, progressData.step_name);
                        }

                        // Add step to operation log
                        const logLevel = progressData.log_level || 'info';
                        addOperationStep(progressData.step_name, logLevel);
                    } else if (progressData.type === 'complete') {
                        console.log('Operation completed');
                        eventSource.close();

                        // Show completion message
                        addOperationStep('Connection test completed', 'success');

                        // Extract results directly from SSE completion event - no duplicate API call
                        setTimeout(() => {
                            hideProgressModal();

                            if (progressData.result_data && progressData.result_data.success) {
                                // Use result data from SSE event - eliminates duplicate connection test
                                handleConnectionTestResult(progressData.result_data);
                            } else if (progressData.result_data) {
                                // Handle error case with result data
                                const errorMsg = progressData.result_data.return_msg ||
                                               progressData.result_data.error ||
                                               'Connection test failed';
                                handleConnectionTestError(errorMsg);
                            } else {
                                // Fallback if no result data
                                handleConnectionTestError('No result data received from server');
                            }
                        }, 3000);
                    } else if (progressData.type === 'error') {
                        console.error('Operation error:', progressData.message);
                        eventSource.close();

                        addOperationStep(`Error: ${progressData.message}`, 'error');

                        setTimeout(() => {
                            hideProgressModal();
                            handleConnectionTestError(progressData.message);
                        }, 2000);
                    } else if (progressData.type === 'ping') {
                        // Keepalive ping, no action needed
                        console.log('SSE keepalive ping received');
                    }
                } catch (e) {
                    console.error('Error parsing progress data:', e);
                }
            };

            eventSource.onerror = function(event) {
                console.error('SSE connection error:', event);
                eventSource.close();
                addOperationStep('Connection to progress stream lost', 'error');

                setTimeout(() => {
                    hideProgressModal();
                    handleConnectionTestError('Progress stream connection lost');
                }, 1000);
            };

            // Set up cleanup when modal is closed
            const originalHideModal = hideProgressModal;
            hideProgressModal = function() {
                if (eventSource && eventSource.readyState !== EventSource.CLOSED) {
                    eventSource.close();
                }
                originalHideModal();
                hideProgressModal = originalHideModal; // Restore original function
            };

        } else {
            throw new Error(result.error || 'Failed to start connection test with progress tracking');
        }

    } catch (error) {
        console.error('Error starting connection test with progress:', error);
        addOperationStep(`Failed to start connection test: ${error.message}`, 'error');

        setTimeout(() => {
            hideProgressModal();
            handleConnectionTestError(error.message);
        }, 1000);
    } finally {
        testConnectionBtn.disabled = false;
        testConnectionBtn.innerHTML = 'Test Connection';
    }
}

// Legacy connection test with simulated progress (fallback)
async function testConnectionLegacy(formData, testConnectionBtn) {
    testConnectionBtn.disabled = true;
    testConnectionBtn.innerHTML = '<span class="inline-flex items-center"><svg class="animate-spin -ml-1 mr-2 h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>Testing...</span>';

    showProgressModal(`Testing Connection to ${formData.firewall}`);

    // Simulate connection test steps with progress updates
    updateProgress(10, `Connecting to ${formData.firewall}:${formData.sshport}...`);
    addOperationStep(`Initiating connection to ${formData.firewall}`, 'info');

    try {
        // Add a small delay to show initial progress
        await new Promise(resolve => setTimeout(resolve, 500));

        updateProgress(25, 'Establishing SSH connection...');
        addOperationStep('Establishing SSH connection', 'info');

        await new Promise(resolve => setTimeout(resolve, 300));

        updateProgress(50, 'Authenticating with credentials...');
        addOperationStep(`Authenticating user: ${formData.username}`, 'info');

        await new Promise(resolve => setTimeout(resolve, 300));

        updateProgress(75, 'Verifying firewall access...');
        addOperationStep('Verifying administrative access', 'info');

        const response = await fetch('/test_connection', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(formData)
        });

        updateProgress(90, 'Processing response...');
        addOperationStep('Retrieving firewall information', 'info');

        const result = await response.json();

        updateProgress(100, 'Connection test completed');

        if (response.ok && result.success) {
            addOperationStep('Connection test successful!', 'success');
            await new Promise(resolve => setTimeout(resolve, 500)); // Show success briefly
            handleConnectionTestResult(result);
        } else {
            addOperationStep(`Connection failed: ${result.error || result.message || 'Unknown error'}`, 'error');
            await new Promise(resolve => setTimeout(resolve, 1000)); // Show error longer
            handleConnectionTestError(result.error || result.message || 'Connection test failed');
        }
    } catch (error) {
        console.error('Test connection error:', error);
        updateProgress(100, 'Connection failed');
        addOperationStep(`Network error: ${error.message}`, 'error');
        await new Promise(resolve => setTimeout(resolve, 1000)); // Show error longer
        handleConnectionTestError(error.message);
    } finally {
        testConnectionBtn.disabled = false;
        testConnectionBtn.innerHTML = 'Test Connection';
        // Hide progress modal after a brief delay
        setTimeout(() => {
            hideProgressModal();
        }, 1500);
    }
}

// New function to handle SSE progress tracking
function startProgressTracking(operationId) {
    console.log(`Starting SSE stream for operation ${operationId}`);
    const eventSource = new EventSource(`/progress/${operationId}`);

    eventSource.onmessage = function(event) {
        const data = JSON.parse(event.data);
        console.log('SSE Event:', data);

        if (data.type === 'progress') {
            // Update progress bar and current step
            if (data.percentage !== undefined) {
                updateProgress(data.percentage, data.step_name);
            }

            // Add operation step
            addOperationStep(data.step_name, getStatusFromLogLevel(data.log_level));

            // Add substeps if present
            if (data.is_substep) {
                // This is already a substep, don't add extra indentation
            } else if (data.substeps && data.substeps.length > 0) {
                // Add any new substeps that aren't already displayed
                data.substeps.forEach(substep => {
                    addOperationStep(`  └─ ${substep.description}`, getStatusFromLogLevel(substep.log_level));
                });
            }
        } else if (data.type === 'complete') {
            // Operation completed
            console.log('Analysis completed:', data);
            eventSource.close();

            if (data.success) {
                updateProgress(100, "Analysis completed successfully");
                addOperationStep("✓ Analysis completed", "success");

                // Handle successful result
                if (data.result_data) {
                    handleAnalysisResult(data.result_data);
                }

                // Auto-hide modal after brief delay
                setTimeout(() => {
                    hideProgressModal();
                }, 3000);
            } else {
                addOperationStep("✗ Analysis failed", "error");
                handleAnalysisError("Analysis failed");

                // Keep modal open for error review
                setTimeout(() => {
                    hideProgressModal();
                }, 5000);
            }
        } else if (data.type === 'ping') {
            // Keep-alive ping, do nothing
            console.log('SSE keepalive ping');
        } else if (data.type === 'error') {
            // Error occurred
            console.error('SSE Error:', data);
            eventSource.close();
            addOperationStep(`✗ Error: ${data.message || data.error}`, "error");
            handleAnalysisError(data.message || data.error || "Unknown error occurred");
        }
    };

    eventSource.onerror = function(event) {
        console.error('SSE Connection Error:', event);
        eventSource.close();
        addOperationStep("✗ Connection error", "error");
        handleAnalysisError("Lost connection to server");
    };

    // Store reference for potential cancellation
    window.currentProgressStream = eventSource;
}

async function handleAnalysisResult(result) {
    console.log('=== ANALYSIS RESULT HANDLER ===');
    console.log('Full result object:', result);
    console.log('Result keys:', Object.keys(result));
    console.log('Result type:', typeof result);

    try {
        // First, ensure the results section is loaded and visible with timeout
        console.log('Loading results section...');

        // Add timeout to prevent hanging
        const timeoutPromise = new Promise((_, reject) =>
            setTimeout(() => reject(new Error('Results section loading timed out')), 10000)
        );

        await Promise.race([
            showSection('results-section'),
            timeoutPromise
        ]);

        console.log('Results section loaded successfully');

        // Add a longer delay to ensure DOM is fully updated and elements are available
        await new Promise(resolve => setTimeout(resolve, 500));

        // Check if results section is properly loaded
        const resultsSection = document.getElementById('results-section');
        if (resultsSection) {
            console.log('Results section confirmed loaded');
            console.log('Results section HTML preview:', resultsSection.innerHTML.substring(0, 300) + '...');

            // Log what elements are available
            const summaryContainer = document.getElementById('tab-content-summary');
            const reportContainer = document.getElementById('markdown-rendered');
            const resultsContent = document.getElementById('results-content');

            console.log('Available elements:', {
                summaryContainer: !!summaryContainer,
                reportContainer: !!reportContainer,
                resultsContent: !!resultsContent
            });
        }

        // Check different possible data structures
        let summaryData = null;
        let markdownReport = null;

        // Try different possible paths for the data
        if (result.results) {
            console.log('Found result.results');
            summaryData = result.results.summary_data;
            markdownReport = result.results.markdown_report;
        } else if (result.summary_data || result.markdown_report) {
            console.log('Found data at root level');
            summaryData = result.summary_data;
            markdownReport = result.markdown_report;
        } else if (result.data) {
            console.log('Found result.data');
            summaryData = result.data.summary_data;
            markdownReport = result.data.markdown_report;
        }

        console.log('Summary data found:', !!summaryData);
        console.log('Markdown report found:', !!markdownReport);

        // Display whatever data we found
        if (summaryData || markdownReport) {
            console.log('Processing results data...');

            if (summaryData) {
                console.log('Displaying summary data...');
                setTimeout(() => {
                    displaySummaryData(summaryData);
                }, 200);
            } else {
                console.log('No summary data to display');
                // Create a basic success message
                setTimeout(() => {
                    displaySummaryData({
                        message: "Analysis completed successfully",
                        status: "success"
                    });
                }, 200);
            }

            if (markdownReport) {
                console.log('Displaying markdown report...');
                setTimeout(() => {
                    displayMarkdownReport(markdownReport);
                }, 400);
            } else {
                console.log('No markdown report to display');
                // Create a basic report from the raw result data
                const fallbackReport = `# Analysis Results\n\n` +
                    `Analysis completed successfully.\n\n` +
                    `## Raw Data\n\n` +
                    `\`\`\`json\n${JSON.stringify(result, null, 2)}\n\`\`\``;
                setTimeout(() => {
                    displayMarkdownReport(fallbackReport);
                }, 400);
            }

            // Enable and highlight the Results nav item
            console.log('Highlighting results navigation...');
            setTimeout(() => {
                highlightResultsNav();
            }, 600);
        } else {
            console.warn('No recognizable results data found in result object');
            console.log('Will create fallback display...');

            // Create fallback display with whatever data we have
            setTimeout(() => {
                displaySummaryData({
                    message: "Analysis completed - data structure not recognized",
                    raw_data: result
                });
            }, 200);

            setTimeout(() => {
                const fallbackReport = `# Analysis Results\n\nAnalysis completed, but data structure was not in expected format.\n\n## Raw Result Data\n\n\`\`\`json\n${JSON.stringify(result, null, 2)}\n\`\`\``;
                displayMarkdownReport(fallbackReport);
            }, 400);

            setTimeout(() => {
                highlightResultsNav();
            }, 600);
        }
    } catch (error) {
        console.error('Error in handleAnalysisResult:', error);

        // Force enable results nav even on error
        enableResultsNav();

        // Fallback: create error display
        setTimeout(() => {
            displaySummaryData({
                message: "Error processing analysis results",
                error: error.message,
                raw_data: result
            });
        }, 200);

        setTimeout(() => {
            const errorReport = `# Analysis Results - Error\n\nAn error occurred while processing the results:\n\n**Error:** ${error.message}\n\n## Raw Data\n\n\`\`\`json\n${JSON.stringify(result, null, 2)}\n\`\`\``;
            displayMarkdownReport(errorReport);
        }, 400);

        setTimeout(() => {
            highlightResultsNav();
        }, 600);
    }

    // Display success message
    console.log('Analysis processing complete');
}

// Function to display summary data in the results section
function displaySummaryData(summaryData) {
    console.log('Displaying summary data:', summaryData);

    const summaryContainer = document.getElementById('tab-content-summary');

    if (!summaryData || Object.keys(summaryData).length === 0) {
        summaryContainer.innerHTML = '<p class="text-gray-500 italic">No summary data available.</p>';
        return;
    }

    // Build summary HTML
    let summaryHTML = '';

    // Device Information Section
    if (summaryData.device_info && Object.keys(summaryData.device_info).length > 0) {
        const device = summaryData.device_info;
        summaryHTML += `
            <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
                <!-- Device Information Card (Left) -->
                <div class="bg-white rounded-lg card-shadow p-6">
                    <h3 class="text-lg font-semibold text-gray-900 mb-4">
                        <span class="inline-flex items-center">
                            <svg class="w-5 h-5 mr-2 text-blue-600" fill="currentColor" viewBox="0 0 20 20">
                                <path d="M3 4a1 1 0 011-1h12a1 1 0 011 1v2a1 1 0 01-1 1H4a1 1 0 01-1-1V4zM3 10a1 1 0 011-1h6a1 1 0 011 1v6a1 1 0 01-1 1H4a1 1 0 01-1-1v-6zM14 4h6v6h-6V4z" clip-rule="evenodd"></path>
                            </svg>
                            Device Information
                        </span>
                    </h3>
                    <div class="space-y-3 text-sm">
                        <div class="flex justify-between">
                            <span class="font-medium text-gray-700">Firewall:</span>
                            <span class="text-gray-900">${device.firewall || 'Unknown'}</span>
                        </div>
                        <div class="flex justify-between">
                            <span class="font-medium text-gray-700">Model:</span>
                            <span class="text-gray-900">${device.device_model || 'Unknown'}</span>
                        </div>
                        <div class="flex justify-between">
                            <span class="font-medium text-gray-700">Firmware:</span>
                            <span class="text-gray-900">${device.firmware_version || 'Unknown'}</span>
                        </div>
                        <div class="flex justify-between">
                            <span class="font-medium text-gray-700">Serial Number:</span>
                            <span class="text-gray-900">${device.serial_number || 'Unknown'}</span>
                        </div>
                    </div>
                </div>

                <!-- Log, Diagnostic, and Configuration Exports Card (Right) -->
                <div class="bg-white rounded-lg card-shadow p-6">
                    <h3 class="text-lg font-semibold text-gray-900 mb-4">
                        <span class="inline-flex items-center">
                            <svg class="w-5 h-5 mr-2 text-green-600" fill="currentColor" viewBox="0 0 20 20">
                                <path fill-rule="evenodd" d="M3 17a1 1 0 011-1h12a1 1 0 011 1v1a1 1 0 01-1 1H4a1 1 0 01-1-1v-1zM3 7a1 1 0 011-1h12a1 1 0 011 1v8a1 1 0 01-1 1H4a1 1 0 01-1-1V7z" clip-rule="evenodd"></path>
                                <path d="M13 3H7v2h6V3z"></path>
                            </svg>
                            Exported Files
                        </span>
                    </h3>
                    <div id="export-status-content" class="space-y-4">
                        <!-- Export content will be populated by JavaScript -->
                    </div>
                </div>
            </div>
        `;
    }


    // NEW: Brief Summary Section
    if (summaryData.brief_summary) {
        const briefSummary = summaryData.brief_summary;

        // Recommendations Section - NOW FIRST
        if (summaryData.recommendations && summaryData.recommendations.length > 0) {
            summaryHTML += `
                <div class="mb-6 p-4 bg-violet-50 border border-violet-200 rounded-lg">
                    <h3 class="text-lg font-semibold text-violet-900 mb-3">
                        <span class="inline-flex items-center">
                            <svg class="w-5 h-5 mr-2 text-violet-600" fill="currentColor" viewBox="0 0 20 20">
                                <path fill-rule="evenodd" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" clip-rule="evenodd"></path>
                            </svg>
                            Recommendations & Next Steps
                        </span>
                    </h3>
                    <ul class="space-y-2">
            `;

            summaryData.recommendations.forEach(recommendation => {
                summaryHTML += `
                    <li class="flex items-start">
                        <span class="text-violet-600 mr-2">•</span>
                        <span class="text-violet-800">${recommendation}</span>
                    </li>
                `;
            });

            summaryHTML += `
                    </ul>
                </div>
            `;
        }

        // Action Items Section - TABLE FORMAT - NOW SECOND
        if (briefSummary.action_items && briefSummary.action_items.length > 0) {
            summaryHTML += `
                <div class="mb-6">
                    <h3 class="text-lg font-semibold text-gray-900 mb-4">
                        <span class="inline-flex items-center">
                            <svg class="w-5 h-5 mr-2 text-red-600" fill="currentColor" viewBox="0 0 20 20">
                                <path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd"></path>
                            </svg>
                            Action Items (${briefSummary.action_items.length})
                        </span>
                    </h3>
                    <p class="text-gray-600 mb-4 text-sm">These items need your attention. Review and prioritize them accordingly.</p>

                    <!-- Action Items Table -->
                    <div class="overflow-x-auto shadow rounded-lg border border-gray-200">
                        <table class="min-w-full divide-y divide-gray-200 bg-white">
                            <thead class="bg-gray-50">
                                <tr>
                                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                        Priority
                                    </th>
                                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                        Config Area
                                    </th>
                                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                        Finding
                                    </th>
                                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                        Action Item
                                    </th>
                                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                        Resources
                                    </th>
                                </tr>
                            </thead>
                            <tbody class="bg-white divide-y divide-gray-200">
            `;

            briefSummary.action_items.forEach((item, index) => {
                // Determine severity styling
                let severityBadgeClass, severityTextClass;
                switch(item.priority.toLowerCase()) {
                    case 'critical':
                        severityBadgeClass = 'bg-red-100 text-red-800';
                        severityTextClass = 'text-red-900';
                        break;
                    case 'high':
                        severityBadgeClass = 'bg-orange-100 text-orange-800';
                        severityTextClass = 'text-orange-900';
                        break;
                    case 'medium':
                        severityBadgeClass = 'bg-yellow-100 text-yellow-800';
                        severityTextClass = 'text-yellow-900';
                        break;
                    case 'low':
                        severityBadgeClass = 'bg-green-100 text-green-800';
                        severityTextClass = 'text-green-900';
                        break;
                    default:
                        severityBadgeClass = 'bg-gray-100 text-gray-800';
                        severityTextClass = 'text-gray-900';
                }

                const rowClass = index % 2 === 0 ? 'bg-white' : 'bg-gray-50';

                summaryHTML += `
                    <tr class="${rowClass}">
                        <td class="px-6 py-4 whitespace-nowrap">
                            <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${severityBadgeClass}">
                                ${item.priority}
                            </span>
<!--                                        ${item.count > 1 ? `<div class="text-xs text-gray-500 mt-1">${item.count} items</div>` : ''}-->
                        </td>

                        <td class="px-6 py-4">
                            <div class="text-xs text-gray-900">${item.area}</div>
                        </td>

                        <td class="px-6 py-4">
                            <div class="text-xs font-medium text-gray-900">${item.finding}</div>
<!--                                        <div class="text-xs text-gray-500 mt-1">${item.check_type.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}</div-->
                        </td>

                        <td class="px-6 py-4">
                            <div class="text-xs text-gray-900">${item.action}</div>
                        </td>

                        <td class="px-6 py-4 whitespace-nowrap">
                            <a href="${item.resource_link}" target="_blank"
                               class="inline-flex items-center text-xs text-blue-600 hover:text-blue-800 hover:underline">
                                <svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                                          d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6v6h-6V4z"></path>
                                </svg>
                                View
                            </a>
                        </td>
                    </tr>
                `;
            });

            summaryHTML += `
                            </tbody>
                        </table>
                    </div>
                </div>
            `;
        } else {
            // Show message when no action items are found
            summaryHTML += `
                <div class="mb-6 p-4 bg-green-50 border border-green-200 rounded-lg">
                    <h3 class="text-lg font-semibold text-green-900 mb-3">
                        <span class="inline-flex items-center">
                            <svg class="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 20 20">
                                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zmM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd"></path>
                        </svg>
                            Action Items (0)
                        </span>
                    </h3>
                    <p class="text-green-800 text-sm">No critical action items found. Your firewall configuration appears to be secure.</p>
                </div>
            `;
        }
    }

    // Top Findings List
    if (summaryData.findings && summaryData.findings.length > 0) {
        summaryHTML += `
            <div class="mb-6 p-4 bg-white border border-gray-200 rounded-lg">
                <h3 class="text-lg font-semibold text-gray-900 mb-3">Configuration Items Found</h3>
                <div class="space-y-2 max-h-64 overflow-y-auto">
        `;

        summaryData.findings.forEach(finding => {
            const severityClass = `priority-${finding.severity}`;
            summaryHTML += `
                <div class="flex justify-between items-center p-2 border-l-4 border-${finding.severity === 'critical' ? 'red' : finding.severity === 'high' ? 'orange' : finding.severity === 'medium' ? 'yellow' : 'green'}-400 bg-gray-50">
                    <div>
                        <span class="font-medium">${finding.check}</span>
                        <span class="ml-2 text-xs ${severityClass} uppercase">${finding.severity}</span>
                    </div>
                    <span class="text-sm font-semibold text-gray-600">${finding.count} item${finding.count > 1 ? 's' : ''}</span>
                </div>
            `;
        });

        summaryHTML += `
                </div>
            </div>
        `;
    }

    summaryContainer.innerHTML = summaryHTML;

    // Populate export status in the new card
    // Transform the actual export data structure to match what populateExportStatus expects
    const transformedExports = transformExportData(summaryData);
    populateExportStatus(transformedExports);

    console.log('Summary data displayed successfully');
}


// Function to populate export status in the summary card
function populateExportStatus(exportData) {
    const exportContainer = document.getElementById('export-status-content');

    if (!exportData || Object.keys(exportData).length === 0) {
        exportContainer.innerHTML = `
            <div class="text-center py-4">
                <svg class="w-8 h-8 mx-auto text-gray-400 mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 00-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2h-2a2 2 0 01-2-2z"></path>
                </svg>
                <p class="text-sm text-gray-500">No exports available</p>
                <p class="text-xs text-gray-400">Enable export options to see files here</p>
            </div>
        `;
        return;
    }

    let exportHTML = '';

    // Configuration Exports Section
    const configExports = exportData.config_exports || {};
    const hasConfigExports = Object.keys(configExports).length > 0;

    exportHTML += `
        <div class="border-b border-gray-200 pb-3 mb-3">
            <h4 class="text-sm font-semibold text-gray-800 mb-2 flex items-center">
                Configuration Files
            </h4>
            <div class="space-y-1">
    `;

    if (hasConfigExports) {
        Object.entries(configExports).forEach(([key, file]) => {
            const statusClass = file.available ? 'text-green-600' : 'text-gray-400';
            const iconClass = file.available ? 'text-green-500' : 'text-gray-300';

            exportHTML += `
                <div class="flex items-center justify-between text-xs">
                    <div class="flex items-center">
                        <svg class="w-3 h-3 mr-1 ${iconClass}" fill="currentColor" viewBox="0 0 24 24">
                            <path fill-rule="evenodd" d="M3 17a1 1 0 011-1h12a1 1 0 011 1v1a1 1 0 01-1 1H4a1 1 0 01-1-1v-1zM3 7a1 1 0 011-1h12a1 1 0 011 1v8a1 1 0 01-1 1H4a1 1 0 01-1-1V7z" clip-rule="evenodd"></path>
                        </svg>
                        <span class="${statusClass}">${file.name || key}</span>
                    </div>
                    <div class="flex items-center space-x-2">
                        ${file.available ?
                            `<button
                                 onclick="downloadExportFile('config', '${key}', '${file.name || key}')"
                                 class="export-download-btn"
                                 title="Download ${file.name || key}"
                                 id="download-config-${key}">
                                 Download
                             </button>`
                            : '<span class="text-gray-400">Not available</span>'
                        }
                    </div>
                </div>
            `;
        });
    } else {
        exportHTML += '<div class="text-xs text-gray-400">No configuration exports</div>';
    }

    exportHTML += `
            </div>
        </div>
    `;

    // Log Exports Section
    const logExports = exportData.log_exports || {};
    const hasLogExports = Object.keys(logExports).length > 0;

    exportHTML += `
        <div class="mb-3">
            <h4 class="text-sm font-semibold text-gray-800 mb-2 flex items-center">
                Diagnostic Files
            </h4>
            <div class="space-y-1">
    `;

    if (hasLogExports) {
        Object.entries(logExports).forEach(([key, file]) => {
            const statusClass = file.available ? 'text-green-600' : 'text-gray-400';
            const iconClass = file.available ? 'text-green-500' : 'text-gray-300';

            exportHTML += `
            <div class="flex items-center justify-between text-xs">
                <div class="flex items-center">
                    <svg class="w-3 h-3 mr-1 ${iconClass}" fill="currentColor" viewBox="0 0 24 24">
                        <path fill-rule="evenodd" d="M3 17a1 1 0 011-1h12a1 1 0 011 1v1a1 1 0 01-1 1H4a1 1 0 01-1-1v-1zM3 7a1 1 0 011-1h12a1 1 0 011 1v8a1 1 0 01-1 1H4a1 1 0 01-1-1V7z" clip-rule="evenodd"></path>
                    </svg>
                    <span class="${statusClass}">${file.name || key}</span>
                </div>
                <div class="flex items-center space-x-2">
                    ${file.available ?
                        `<button
                             onclick="downloadExportFile('log', '${key}', '${file.name || key}')"
                             class="export-download-btn"
                             title="Download ${file.name || key}"
                             id="download-log-${key}">
                             Download
                         </button>`
                        : '<span class="text-gray-400">Not available</span>'
                    }
                </div>
            </div>
            `;
        });
    } else {
        exportHTML += '<div class="text-xs text-gray-400">No log exports</div>';
    }

    exportHTML += `
            </div>
        </div>
    `;


    exportContainer.innerHTML = exportHTML;
}

// Function to transform export data structure to match what populateExportStatus expects
function transformExportData(summaryData) {
    if (!summaryData) {
        return {};
    }

    const transformedData = {
        config_exports: {},
        log_exports: {}
    };

    // Transform TSR data
    if (summaryData.export_status && summaryData.export_status.tsr && summaryData.export_status.tsr.successful !== undefined) {
        transformedData.log_exports.tsr = {
            available: summaryData.export_status.tsr.successful,
            name: summaryData.export_status.tsr.file_path ? summaryData.export_status.tsr.file_path.split('/').pop() : 'TSR',
        };
    }

    // Transform settings/preferences data
    if (summaryData.export_status && summaryData.export_status.settings && summaryData.export_status.settings.successful !== undefined) {
        transformedData.config_exports.preferences = {
            available: summaryData.export_status.settings.successful,
            name: summaryData.export_status.settings.file_path ? summaryData.export_status.settings.file_path.split('/').pop() : 'Preferences Export',
        };
    }

    return transformedData;
}

// Function to display markdown report in the results section
function displayMarkdownReport(markdownContent) {
    console.log('Displaying markdown report');
    console.log('Looking for markdown-rendered element...');

    const reportContainer = document.getElementById('markdown-rendered');
    console.log('Report container found:', reportContainer);

    if (!reportContainer) {
        console.error('Markdown report container not found - trying fallback');

        // Fallback: try to find results-content area
        const resultsContent = document.getElementById('results-content');
        if (resultsContent) {
            console.log('Using fallback: displaying markdown in results-content area');
            resultsContent.innerHTML += `
                <div class="mt-6 border border-gray-200 rounded-lg p-6 bg-white">
                    <h3 class="text-lg font-semibold text-gray-900 mb-4">Playbook Report</h3>
                    <pre class="whitespace-pre-wrap text-sm bg-gray-50 p-4 rounded overflow-auto">${markdownContent}</pre>
                </div>
            `;

            // Store the raw markdown for potential download functionality
            window.currentMarkdownReport = markdownContent;
            return;
        } else {
            console.error('Neither markdown-rendered nor results-content found');
            return;
        }
    }

    try {
        // Check if marked library is available for markdown parsing
        if (typeof marked !== 'undefined') {
            console.log('Using marked library to render markdown');
            // Render markdown to HTML
            const htmlContent = marked.parse(markdownContent);
            reportContainer.innerHTML = htmlContent;
        } else {
            console.log('Marked library not available, using fallback text display');
            // Fallback: display as preformatted text
            reportContainer.innerHTML = `<pre class="whitespace-pre-wrap text-sm">${markdownContent}</pre>`;
        }

        // Store the raw markdown for download functionality
        window.currentMarkdownReport = markdownContent;
        console.log('Markdown report displayed successfully');

        // Set up report tab functionality
        setupReportTabFunctionality();

    } catch (error) {
        console.error('Error rendering markdown report:', error);
        reportContainer.innerHTML = `
            <div class="text-red-600 bg-red-50 border border-red-200 rounded p-4">
                <strong>Error rendering report:</strong> ${error.message}
                <details class="mt-2">
                    <summary class="cursor-pointer">Raw markdown content</summary>
                    <pre class="mt-2 text-xs bg-gray-100 p-2 rounded overflow-auto">${markdownContent}</pre>
                </details>
            </div>
        `;
    }
}

// Function to highlight/enable the Results navigation item
function highlightResultsNav() {
    console.log('Highlighting results navigation');

    // Enable the results navigation button
    enableResultsNav();

    // Add visual highlight to indicate new results are available
    const resultsButton = document.getElementById('nav-results');
    if (resultsButton) {
        resultsButton.classList.add('nav-btn-highlight');

        // Add a subtle notification indicator
        if (!resultsButton.querySelector('.notification-dot')) {
            const dot = document.createElement('span');
            dot.className = 'notification-dot absolute -top-1 -right-1 w-3 h-3 bg-green-500 rounded-full border-2 border-white';
            resultsButton.style.position = 'relative';
            resultsButton.appendChild(dot);
        }
    }

    // Update results card on dashboard if visible
    const resultsCard = document.getElementById('results-card');
    const resultsCardStatus = document.getElementById('results-card-status');

    if (resultsCard) {
        resultsCard.classList.remove('opacity-50');
        resultsCard.classList.add('opacity-100');
        resultsCard.style.cursor = 'pointer';
    }

    if (resultsCardStatus) {
        resultsCardStatus.textContent = 'New results available - Click to view';
        resultsCardStatus.classList.add('text-green-600', 'font-semibold');
    }
}

// Function to set up report tab functionality
function setupReportTabFunctionality() {
    // Set up tab switching
    const summaryTab = document.getElementById('tab-summary');
    const reportTab = document.getElementById('tab-report');
    const summaryContent = document.getElementById('tab-content-summary');
    const reportContent = document.getElementById('tab-content-report');

    if (summaryTab && reportTab && summaryContent && reportContent) {
        summaryTab.addEventListener('click', function() {
            // Switch to summary tab
            summaryTab.classList.add('tab-active', 'border-blue-500', 'text-blue-600');
            summaryTab.classList.remove('tab-inactive', 'border-transparent', 'text-gray-500');
            reportTab.classList.add('tab-inactive', 'border-transparent', 'text-gray-500');
            reportTab.classList.remove('tab-active', 'border-blue-500', 'text-blue-600');

            summaryContent.classList.remove('hide');
            reportContent.classList.add('hide');
        });

        reportTab.addEventListener('click', function() {
            // Switch to report tab
            reportTab.classList.add('tab-active', 'border-blue-500', 'text-blue-600');
            reportTab.classList.remove('tab-inactive', 'border-transparent', 'text-gray-500');
            summaryTab.classList.add('tab-inactive', 'border-transparent', 'text-gray-500');
            summaryTab.classList.remove('tab-active', 'border-blue-500', 'text-blue-600');

            reportContent.classList.remove('hide');
            summaryContent.classList.add('hide');
        });
    }

    // Set up download and print functionality
    setupReportDownloadHandlers();
}

// Function to set up report download handlers
function setupReportDownloadHandlers() {
    const downloadMdBtn = document.getElementById('download-report-md');
    const downloadHtmlBtn = document.getElementById('download-report-html');
    const toggleViewBtn = document.getElementById('toggle-report-view');

    if (downloadMdBtn) {
        downloadMdBtn.addEventListener('click', function() {
            if (window.currentMarkdownReport) {
                downloadFile(window.currentMarkdownReport, 'playbook-analysis-report.md', 'text/markdown');
            }
        });
    }

    if (downloadHtmlBtn) {
        downloadHtmlBtn.addEventListener('click', function() {
            const reportContainer = document.getElementById('markdown-rendered');
            if (reportContainer) {
                const htmlContent = `
<!DOCTYPE html>
<html>
<head>
    <title>SonicWall Playbook Analysis Report</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
        h1, h2, h3 { color: #333; }
        table { border-collapse: collapse; width: 100%; margin: 1em 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .alert { padding: 10px; margin: 10px 0; border-radius: 4px; }
        .alert-danger { background-color: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; }
        .alert-warning { background-color: #fff3cd; border: 1px solid #ffeaa7; color: #856404; }
        .alert-info { background-color: #d1ecf1; border: 1px solid #bee5eb; color: #0c5460; }
    </style>
</head>
<body>
    ${reportContainer.innerHTML}
</body>
</html>`;
                downloadFile(htmlContent, 'playbook-analysis-report.html', 'text/html');
            }
        });
    }

    if (toggleViewBtn) {
        toggleViewBtn.addEventListener('click', function() {
            const reportContainer = document.getElementById('markdown-rendered');
            if (reportContainer && window.currentMarkdownReport) {
                if (toggleViewBtn.textContent.includes('Raw')) {
                    // Switch to raw view
                    reportContainer.innerHTML = `<pre class="whitespace-pre-wrap text-sm bg-gray-100 p-4 rounded overflow-auto">${window.currentMarkdownReport}</pre>`;
                    toggleViewBtn.textContent = 'Show Formatted';
                } else {
                    // Switch to formatted view
                    if (typeof marked !== 'undefined') {
                        reportContainer.innerHTML = marked.parse(window.currentMarkdownReport);
                    }
                    toggleViewBtn.textContent = 'Show Raw';
                }
            }
        });
    }
}

// Utility function to download files
function downloadFile(content, filename, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// Initialize form functionality when DOM is loaded
function initializeForms() {
    console.log('Initializing forms');

    // Password option radio button functionality
    const passwordRadios = document.querySelectorAll('input[name="password-option"]');
    const tempPasswordInput = document.getElementById('temp-password');

    passwordRadios.forEach(radio => {
        radio.addEventListener('change', function(event) {
            if (event.target.value === 'custom') {
                tempPasswordInput.disabled = false;
                tempPasswordInput.focus();
            } else {
                tempPasswordInput.disabled = true;
                tempPasswordInput.value = '';
            }
        });
    });

    // Reset Form button functionality
    const resetFormBtn = document.getElementById('reset-form-btn');
    if (resetFormBtn) {
        resetFormBtn.addEventListener('click', function() {
            console.log('Reset Form button clicked');
            resetSingleTargetForm();
        });
    }

    // Test Connection button functionality with progress integration
    const testConnectionBtn = document.getElementById('test-connection-btn');
    if (testConnectionBtn) {
        testConnectionBtn.addEventListener('click', async function(e) {
            e.preventDefault(); // Prevent any default form submission behavior
            console.log('Test Connection button clicked');

            // Gather form data
            const formData = {
                firewall: document.getElementById('firewall-ip').value.trim(),
                username: document.getElementById('admin-username').value.trim(),
                password: document.getElementById('admin-password').value.trim(),
                sshport: document.getElementById('ssh-port').value.trim(),
                force_password_change: document.getElementById('force-password-change').checked.toString(),
                unbind_totp: document.getElementById('unbind-totp').checked.toString(),
                export_settings: document.getElementById('export-settings').checked.toString(),
                export_tsr: document.getElementById('export-tsr').checked.toString(),
                temp_password: document.getElementById('temp-password').value.trim(),
                randomize_temp_password: document.querySelector('input[name="password-option"]:checked').value === 'random' ? 'True' : 'False'
            };

            console.log('Testing connection to:', formData.firewall);
            console.log('Form Data:', formData);

            // Validate required fields before showing progress
            if (!formData.firewall || !formData.username || !formData.password) {
                window.alert('Please fill in all required fields (Firewall IP, Username, Password)');
                return;
            }

            // Security level is always valid since dropdown has a default value
            const useProgressStreaming = true; // Enable SSE progress streaming

            if (useProgressStreaming) {
                await testConnectionWithProgress(formData, testConnectionBtn);
            } else {
                await testConnectionLegacy(formData, testConnectionBtn);
            }
        });
    }

    // Run Security Analysis button functionality with progress tracking
    const runAnalysisBtn = document.getElementById('run-analysis-btn');
    if (runAnalysisBtn) {
        runAnalysisBtn.addEventListener('click', async function(e) {
            e.preventDefault();
            console.log('Run Playbook button clicked');

            // Gather form data
            const formData = {
                firewall: document.getElementById('firewall-ip').value.trim(),
                username: document.getElementById('admin-username').value.trim(),
                password: document.getElementById('admin-password').value.trim(),
                sshport: document.getElementById('ssh-port').value.trim(),
                force_password_change: document.getElementById('force-password-change').checked.toString(),
                unbind_totp: document.getElementById('unbind-totp').checked.toString(),
                export_settings: document.getElementById('export-settings').checked.toString(),
                export_tsr: document.getElementById('export-tsr').checked.toString(),
                temp_password: document.getElementById('temp-password').value.trim(),
                randomize_temp_password: document.querySelector('input[name="password-option"]:checked').value === 'random' ? 'True' : 'False',
                severity: document.getElementById('security-level-select').value
            };

            console.log(formData)

            // Validate required fields
            if (!formData.firewall || !formData.username || !formData.password) {
                window.alert('Please fill in all required fields (Firewall IP, Username, Password)');
                return;
            }

            try {
                // Show progress modal immediately
                showProgressModal("Playbook Operation Progress");

                // Disable button and show loading state
                runAnalysisBtn.disabled = true;
                runAnalysisBtn.innerHTML = '<span class="inline-flex items-center"><svg class="animate-spin -ml-1 mr-2 h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>Starting Analysis...</span>';

                // Start the operation
                const response = await fetch('/single_analysis', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(formData)
                });

                const result = await response.json();

                if (response.ok && result.success && result.operation_id) {
                    // Start SSE connection for progress updates
                    startProgressTracking(result.operation_id);
                } else {
                    hideProgressModal();
                    handleAnalysisError(result.error || 'Failed to start analysis');
                }

            } catch (error) {
                console.error('Playbook analysis start error:', error);
                hideProgressModal();
                handleAnalysisError(error.message);
            } finally {
                runAnalysisBtn.disabled = false;
                runAnalysisBtn.innerHTML = 'Run Playbook';
            }
        });
    }
}

// Export functions for global access
window.handleConnectionTestResult = handleConnectionTestResult;
window.handleConnectionTestError = handleConnectionTestError;
window.handleAnalysisError = handleAnalysisError;
window.handleAnalysisResult = handleAnalysisResult;
window.resetSingleTargetForm = resetSingleTargetForm;
window.testConnectionWithProgress = testConnectionWithProgress;
window.testConnectionLegacy = testConnectionLegacy;
window.startProgressTracking = startProgressTracking;
window.initializeForms = initializeForms;
