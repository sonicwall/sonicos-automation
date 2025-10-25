// Progress Modal Functions for SonicWall Credential Reset Tool
// Handles progress tracking, modal display, and operation feedback

// Progress Modal Functions
function showProgressModal(title = "Operation Progress") {
    const modal = document.getElementById('progress-modal');
    const modalTitle = modal.querySelector('h3');
    modalTitle.textContent = title;
    modal.classList.remove('hide');
    resetProgressModal();
}

// Function to load progress modal content
async function loadProgressModalContent() {
    try {
        const response = await fetch('sections/progress.html');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const progressHTML = await response.text();
        document.getElementById('progress-modal-container').innerHTML = progressHTML;

        // Ensure modal is hidden after loading
        const modal = document.getElementById('progress-modal');
        if (modal) {
            modal.classList.add('hide');
        }

        // Set up progress modal event listeners after loading
        setupProgressModalEventListeners();
    } catch (error) {
        console.error('Error loading progress modal:', error);
        // Fallback: create a basic progress modal structure
        document.getElementById('progress-modal-container').innerHTML = `
            <div id="progress-modal" class="fixed inset-0 bg-gray-600 bg-opacity-50 hide z-50">
                <div class="flex items-center justify-center min-h-screen p-4">
                    <div class="bg-white rounded-lg p-8 max-w-lg w-full mx-4">
                        <h3 class="text-lg font-semibold text-gray-900 mb-4">Operation Progress</h3>
                        <div class="mb-4">
                            <p id="current-target" class="text-sm text-gray-600 mb-2">Initializing...</p>
                            <div class="w-full bg-gray-200 rounded-full h-2 mb-2">
                                <div id="progress-bar" class="bg-blue-600 h-2 rounded-full" style="width: 0%"></div>
                            </div>
                            <p id="progress-percentage" class="text-xs text-gray-500">0%</p>
                        </div>
                        <div id="operation-steps" class="space-y-1 mb-4 max-h-64 overflow-y-auto"></div>
                        <div class="flex justify-end">
                            <button id="cancel-operation-btn" class="bg-gray-600 text-white px-4 py-2 rounded-md hover:bg-gray-700">Close</button>
                        </div>
                    </div>
                </div>
            </div>
        `;
        setupProgressModalEventListeners();
    }
}

// Function to set up progress modal event listeners
function setupProgressModalEventListeners() {
    // Cancel operation button functionality
    const cancelOperationBtn = document.getElementById('cancel-operation-btn');
    if (cancelOperationBtn) {
        cancelOperationBtn.addEventListener('click', function() {
            console.log('Operation cancelled by user');

            // Close any active SSE streams
            if (window.currentProgressStream) {
                console.log('Closing active progress stream');
                window.currentProgressStream.close();
                window.currentProgressStream = null;
            }

            hideProgressModal();

            // Reset any ongoing operations
            const testBtn = document.getElementById('test-connection-btn');
            const analysisBtn = document.getElementById('run-analysis-btn');

            if (testBtn && testBtn.disabled) {
                testBtn.disabled = false;
                testBtn.innerHTML = 'Test Connection';
            }

            if (analysisBtn && analysisBtn.disabled) {
                analysisBtn.disabled = false;
                analysisBtn.innerHTML = 'Run Playbook';
            }
        });
    }
}

function hideProgressModal() {
    const modal = document.getElementById('progress-modal');
    modal.classList.add('hide');
}

function resetProgressModal() {
    updateProgress(0, "Initializing...");
    clearOperationSteps();
}

function updateProgress(percentage, currentStep) {
    const progressBar = document.getElementById('progress-bar');
    const progressText = document.getElementById('progress-percentage');
    const currentTarget = document.getElementById('current-target');

    progressBar.style.width = `${percentage}%`;
    progressText.textContent = `${percentage}%`;
    currentTarget.textContent = currentStep;
}

function addOperationStep(step, status = 'info') {
    const stepsContainer = document.getElementById('operation-steps');
    const stepElement = document.createElement('div');
    stepElement.className = `text-xs rounded status-${status}`;
    stepElement.textContent = step;
    stepsContainer.appendChild(stepElement);
    stepsContainer.scrollTop = stepsContainer.scrollHeight;
}

function clearOperationSteps() {
    const stepsContainer = document.getElementById('operation-steps');
    stepsContainer.innerHTML = '';
}

// Helper function to map log levels to status classes
function getStatusFromLogLevel(logLevel) {
    switch(logLevel) {
        case 'error':
        case 'ERROR':
            return 'error';
        case 'success':
        case 'SUCCESS':
            return 'success';
        case 'warning':
        case 'WARNING':
            return 'warning';
        default:
            return 'info';
    }
}

// Main initialization function
async function initializeProgressModal() {
    console.log('Initializing progress modal...');

    try {
        // Load progress modal content
        await loadProgressModalContent();

        console.log('Progress modal initialized successfully');
    } catch (error) {
        console.error('Error initializing progress modal:', error);
    }
}

// Export functions for global access
window.showProgressModal = showProgressModal;
window.hideProgressModal = hideProgressModal;
window.resetProgressModal = resetProgressModal;
window.updateProgress = updateProgress;
window.addOperationStep = addOperationStep;
window.clearOperationSteps = clearOperationSteps;
window.getStatusFromLogLevel = getStatusFromLogLevel;
window.loadProgressModalContent = loadProgressModalContent;
window.setupProgressModalEventListeners = setupProgressModalEventListeners;
window.initializeProgressModal = initializeProgressModal;
