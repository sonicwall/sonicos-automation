// Navigation functionality for SonicWall Credential Reset Tool
// Handles section switching, navigation state, and dynamic content loading

// Content cache to avoid repeated requests
const contentCache = {};

// Section-to-file mapping
const sectionFiles = {
    'dashboard-section': 'sections/dashboard.html',
    'single-section': 'sections/single-target-content.html',
    'batch-section': 'sections/batch-operations-content.html',
    'results-section': 'sections/results-content.html',
    'help-section': 'sections/help.html'
};

// Function to load section content from HTML files
async function loadSectionContent(sectionId) {
    // Check if content is already cached
    if (contentCache[sectionId]) {
        return contentCache[sectionId];
    }

    const fileName = sectionFiles[sectionId];
    if (!fileName) {
        console.error(`No file mapping found for section: ${sectionId}`);
        return `<div class="text-center py-8"><h2 class="text-xl text-gray-600">Section not found</h2></div>`;
    }

    try {
        console.log(`Loading content for ${sectionId} from ${fileName}`);
        const response = await fetch(fileName);

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const content = await response.text();

        // Cache the content
        contentCache[sectionId] = content;

        return content;
    } catch (error) {
        console.error(`Error loading content for ${sectionId}:`, error);

        // Return fallback content
        const fallbackContent = `
            <div class="text-center py-8">
                <div class="text-red-600 mb-4">
                    <svg class="w-12 h-12 mx-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z"></path>
                    </svg>
                </div>
                <h2 class="text-xl text-gray-600">Content could not be loaded</h2>
                <p class="text-gray-500 mt-2">Please check your connection and try again.</p>
            </div>
        `;

        return fallbackContent;
    }
}

// Function to show loading state
function showLoadingState(sectionId) {
    const element = document.getElementById(sectionId);
    if (element) {
        element.innerHTML = `
            <div class="text-center py-12">
                <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
                <p class="text-gray-600">Loading content...</p>
            </div>
        `;
    }
}

// Function to load navigation content
async function loadNavigationContent() {
    try {
        const response = await fetch('sections/navigation.html');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const navigationHTML = await response.text();
        document.getElementById('navigation-header').innerHTML = navigationHTML;

        // Set up navigation event listeners after loading
        setupNavigationEventListeners();
    } catch (error) {
        console.error('Error loading navigation:', error);
        // Fallback: create a basic navigation structure
        document.getElementById('navigation-header').innerHTML = `
            <nav class="gradient-bg shadow-lg">
                <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                    <div class="flex justify-between h-16">
                        <div class="flex items-center">
                            <h1 class="text-white text-xl font-bold">SonicWall Credential Reset Tool</h1>
                        </div>
                        <div class="flex items-center space-x-4">
                            <button id="nav-dashboard" class="nav-btn text-white hover:text-gray-200 px-3 py-2 rounded-md text-sm font-medium">Dashboard</button>
                            <button id="nav-single" class="nav-btn text-white hover:text-gray-200 px-3 py-2 rounded-md text-sm font-medium">Single Target</button>
                            <button id="nav-batch" class="nav-btn text-white hover:text-gray-200 px-3 py-2 rounded-md text-sm font-medium">Batch Operations</button>
                            <button id="nav-results" class="nav-btn nav-btn-disabled text-white hover:text-gray-200 px-3 py-2 rounded-md text-sm font-medium">Results</button>
                            <button id="nav-help" class="nav-btn text-white hover:text-gray-200 px-3 py-2 rounded-md text-sm font-medium">Help</button>
                        </div>
                    </div>
                </div>
            </nav>
        `;
        setupNavigationEventListeners();
    }
}

// Function to set up navigation event listeners
function setupNavigationEventListeners() {
    // Add click event listeners to navigation buttons
    const navButtons = document.querySelectorAll('.nav-btn');
    navButtons.forEach(button => {
        button.addEventListener('click', function() {
            // Don't navigate if button is disabled
            if (this.classList.contains('nav-btn-disabled')) {
                return;
            }

            const sectionId = this.id.replace('nav-', '') + '-section';
            showSection(sectionId);
        });
    });
}

// Enhanced showSection function with content loading
async function showSection(sectionId) {
    console.log('Showing section:', sectionId);

    try {
        const sections = ['dashboard-section', 'single-section', 'batch-section', 'results-section', 'help-section'];

        // Hide all sections first
        sections.forEach(section => {
            const element = document.getElementById(section);
            if (element) {
                element.classList.add('hide');
                element.classList.remove('show');
            }
        });

        // Show loading state for target section
        const targetElement = document.getElementById(sectionId);
        if (!targetElement) {
            console.error(`Target element not found: ${sectionId}`);
            return Promise.reject(new Error(`Target element not found: ${sectionId}`));
        }

        targetElement.classList.remove('hide');
        targetElement.classList.add('show');

        // Special handling for results-section - it has embedded content, don't overwrite it
        if (sectionId === 'results-section') {
            console.log(`Results section has embedded content, skipping external loading`);

            // Check if the required elements exist
            const summaryContainer = document.getElementById('tab-content-summary');
            const reportContainer = document.getElementById('markdown-rendered');
            const resultsContent = document.getElementById('results-content');

            if (summaryContainer && reportContainer && resultsContent) {
                console.log(`Results section embedded elements confirmed present`);
                // Re-initialize any JavaScript functionality for the loaded content
                console.log(`Initializing section-specific features for ${sectionId}`);
                initializeSectionSpecificFeatures(sectionId);

                // Update navigation active state
                updateNavigationState(sectionId);

                console.log(`Section ${sectionId} loaded successfully (embedded content)`);
                return Promise.resolve();
            } else {
                console.log(`Results section embedded elements missing, falling back to external loading`);
            }
        }

        // For other sections or if results section elements are missing, load external content
        // Show loading state if content not cached
        if (!contentCache[sectionId]) {
            console.log(`Content not cached for ${sectionId}, showing loading state`);
            showLoadingState(sectionId);
        }

        // Load and inject content
        console.log(`Loading content for ${sectionId}...`);
        const content = await loadSectionContent(sectionId);
        console.log(`Content loaded for ${sectionId}, injecting into DOM`);
        targetElement.innerHTML = content;

        // Re-initialize any JavaScript functionality for the loaded content
        console.log(`Initializing section-specific features for ${sectionId}`);
        initializeSectionSpecificFeatures(sectionId);

        // Update navigation active state
        updateNavigationState(sectionId);

        console.log(`Section ${sectionId} loaded successfully`);
        return Promise.resolve();

    } catch (error) {
        console.error(`Error in showSection for ${sectionId}:`, error);

        // Show error state in the target element if it exists
        const targetElement = document.getElementById(sectionId);
        if (targetElement) {
            targetElement.innerHTML = `
                <div class="text-center py-8">
                    <div class="text-red-600 mb-4">
                        <svg class="w-12 h-12 mx-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z"></path>
                        </svg>
                    </div>
                    <h2 class="text-xl text-gray-600">Failed to load content</h2>
                    <p class="text-gray-500 mt-2">Error: ${error.message}</p>
                </div>
            `;
        }

        return Promise.reject(error);
    }
}

// Function to update navigation button states
function updateNavigationState(sectionId) {
    const navButtons = document.querySelectorAll('.nav-btn');
    navButtons.forEach(btn => {
        btn.classList.remove('bg-white', 'text-gray-900');
        btn.classList.add('text-white', 'hover:text-gray-200');
    });

    // Special handling for results section - enable the nav button first
    if (sectionId === 'results-section') {
        enableResultsNav();
    }

    // Highlight active nav button
    const activeButton = document.getElementById(`nav-${sectionId.replace('-section', '')}`);
    if (activeButton && !activeButton.classList.contains('nav-btn-disabled')) {
        activeButton.classList.add('bg-white', 'text-gray-900');
        activeButton.classList.remove('text-white', 'hover:text-gray-200');
    }
}

// Function to initialize section-specific features after content is loaded
function initializeSectionSpecificFeatures(sectionId) {
    switch(sectionId) {
        case 'dashboard-section':
            // Initialize dashboard-specific features
            initializeDashboardFeatures();
            break;
        case 'single-section':
            // Initialize single target form features
            if (typeof initializeForms === 'function') {
                initializeForms();
            }
            break;
        case 'batch-section':
            // Initialize batch operations features
            if (typeof initializeForms === 'function') {
                initializeForms();
            }
            break;
        case 'results-section':
            // Initialize results features
            initializeResults();
            break;
        case 'help-section':
            // Initialize help features (markdown rendering, etc.)
            initializeHelpFeatures();
            break;
    }
}

// Function to initialize dashboard-specific features
function initializeDashboardFeatures() {
    // Set up card click handlers for navigation
    const cards = document.querySelectorAll('.cursor-pointer[onclick]');
    cards.forEach(card => {
        // Remove inline onclick and add proper event listener
        const onclickAttr = card.getAttribute('onclick');
        if (onclickAttr) {
            card.removeAttribute('onclick');
            card.addEventListener('click', function() {
                eval(onclickAttr);
            });
        }
    });
}

// Function to initialize results section features
function initializeResults() {
    console.log('Initializing results section features...');

    // Initialize tab switching functionality
    setupResultsTabs();

    // Show the results tabs container if it's hidden
    const tabsContainer = document.getElementById('results-tabs-container');
    if (tabsContainer) {
        tabsContainer.classList.remove('hide');
        tabsContainer.classList.add('show');
    }

    // Ensure summary tab is active by default
    showResultsTab('summary');

    console.log('Results section features initialized successfully');
}

// Function to set up results tab switching
function setupResultsTabs() {
    const summaryTab = document.getElementById('tab-summary');
    const reportTab = document.getElementById('tab-report');

    if (summaryTab) {
        summaryTab.addEventListener('click', () => showResultsTab('summary'));
    }

    if (reportTab) {
        reportTab.addEventListener('click', () => showResultsTab('report'));
    }

    console.log('Results tabs event listeners setup complete');
}

// Function to show specific results tab
function showResultsTab(tabName) {
    console.log(`Switching to ${tabName} tab`);

    // Update tab button states
    const summaryTab = document.getElementById('tab-summary');
    const reportTab = document.getElementById('tab-report');

    if (summaryTab && reportTab) {
        // Remove active state from both tabs
        summaryTab.classList.remove('tab-active', 'border-blue-500', 'text-blue-600');
        summaryTab.classList.add('tab-inactive', 'border-transparent', 'text-gray-500');

        reportTab.classList.remove('tab-active', 'border-blue-500', 'text-blue-600');
        reportTab.classList.add('tab-inactive', 'border-transparent', 'text-gray-500');

        // Add active state to selected tab
        if (tabName === 'summary') {
            summaryTab.classList.remove('tab-inactive', 'border-transparent', 'text-gray-500');
            summaryTab.classList.add('tab-active', 'border-blue-500', 'text-blue-600');
        } else {
            reportTab.classList.remove('tab-inactive', 'border-transparent', 'text-gray-500');
            reportTab.classList.add('tab-active', 'border-blue-500', 'text-blue-600');
        }
    }

    // Show/hide tab content
    const summaryContent = document.getElementById('tab-content-summary');
    const reportContent = document.getElementById('tab-content-report');

    if (summaryContent && reportContent) {
        if (tabName === 'summary') {
            summaryContent.classList.remove('hide');
            summaryContent.classList.add('show');
            reportContent.classList.remove('show');
            reportContent.classList.add('hide');
        } else {
            reportContent.classList.remove('hide');
            reportContent.classList.add('show');
            summaryContent.classList.remove('show');
            summaryContent.classList.add('hide');
        }
    }

    console.log(`Tab switch to ${tabName} completed`);
}

// Function to initialize help section features
function initializeHelpFeatures() {
    // Handle markdown rendering if needed
    const markdownElements = document.querySelectorAll('[data-markdown]');
    markdownElements.forEach(element => {
        if (typeof marked !== 'undefined') {
            element.innerHTML = marked.parse(element.textContent);
        }
    });
}

// Function to handle results card clicks on dashboard
function handleResultsCardClick() {
    const resultsButton = document.getElementById('nav-results');
    if (resultsButton && !resultsButton.classList.contains('nav-btn-disabled')) {
        showSection('results-section');
    }
}

// Function to disable the Results nav item
function disableResultsNav() {
    const resultsButton = document.getElementById('nav-results');
    const resultsCard = document.getElementById('results-card');
    const resultsCardStatus = document.getElementById('results-card-status');

    if (resultsButton) {
        resultsButton.classList.add('nav-btn-disabled');
        resultsButton.classList.remove('nav-btn-enabled', 'nav-btn-highlight');
    }

    if (resultsCard) {
        resultsCard.classList.add('opacity-50');
        resultsCard.classList.remove('opacity-100');
        resultsCard.style.cursor = 'not-allowed';
    }

    if (resultsCardStatus) {
        resultsCardStatus.textContent = 'No results available';
    }
}

// Function to enable the Results nav item
function enableResultsNav() {
    const resultsButton = document.getElementById('nav-results');
    const resultsCard = document.getElementById('results-card');
    const resultsCardStatus = document.getElementById('results-card-status');

    if (resultsButton) {
        resultsButton.classList.remove('nav-btn-disabled');
        resultsButton.classList.add('nav-btn-enabled');
    }

    if (resultsCard) {
        resultsCard.classList.remove('opacity-50');
        resultsCard.classList.add('opacity-100');
        resultsCard.style.cursor = 'pointer';
    }

    if (resultsCardStatus) {
        resultsCardStatus.textContent = 'Click to view results';
    }
}

// Function to preload critical sections
async function preloadCriticalSections() {
    try {
        // Preload dashboard and help sections as they're most commonly accessed
        await Promise.all([
            loadSectionContent('dashboard-section'),
            loadSectionContent('help-section')
        ]);
        console.log('Critical sections preloaded successfully');
    } catch (error) {
        console.error('Error preloading critical sections:', error);
    }
}

// Main initialization function
async function initializeNavigation() {
    console.log('Initializing navigation system...');

    try {
        // Load navigation header
        await loadNavigationContent();

        // Preload critical sections
        await preloadCriticalSections();

        console.log('Navigation system initialized successfully');
    } catch (error) {
        console.error('Error initializing navigation:', error);
    }
}

// Function to handle results card clicks on dashboard
function handleResultsCardClick() {
    const resultsButton = document.getElementById('nav-results');
    if (resultsButton && !resultsButton.classList.contains('nav-btn-disabled')) {
        showSection('results-section');
    }
}

// Function to disable the Results nav item
function disableResultsNav() {
    const resultsButton = document.getElementById('nav-results');
    const resultsCard = document.getElementById('results-card');
    const resultsCardStatus = document.getElementById('results-card-status');

    if (resultsButton) {
        resultsButton.classList.add('nav-btn-disabled');
        resultsButton.classList.remove('nav-btn-enabled', 'nav-btn-highlight');
    }

    if (resultsCard) {
        resultsCard.classList.add('opacity-50');
        resultsCard.classList.remove('opacity-100');
        resultsCard.style.cursor = 'not-allowed';
    }

    if (resultsCardStatus) {
        resultsCardStatus.textContent = 'No results available';
    }
}

// Function to enable the Results nav item
function enableResultsNav() {
    const resultsButton = document.getElementById('nav-results');
    const resultsCard = document.getElementById('results-card');
    const resultsCardStatus = document.getElementById('results-card-status');

    if (resultsButton) {
        resultsButton.classList.remove('nav-btn-disabled');
        resultsButton.classList.add('nav-btn-enabled');
    }

    if (resultsCard) {
        resultsCard.classList.remove('opacity-50');
        resultsCard.classList.add('opacity-100');
        resultsCard.style.cursor = 'pointer';
    }

    if (resultsCardStatus) {
        resultsCardStatus.textContent = 'Click to view results';
    }
}

// Function to preload critical sections
async function preloadCriticalSections() {
    try {
        // Preload dashboard and help sections as they're most commonly accessed
        await Promise.all([
            loadSectionContent('dashboard-section'),
            loadSectionContent('help-section')
        ]);
        console.log('Critical sections preloaded successfully');
    } catch (error) {
        console.error('Error preloading critical sections:', error);
    }
}

// Main initialization function
async function initializeNavigation() {
    console.log('Initializing navigation system...');

    try {
        // Load navigation header
        await loadNavigationContent();

        // Preload critical sections
        await preloadCriticalSections();

        console.log('Navigation system initialized successfully');
    } catch (error) {
        console.error('Error initializing navigation:', error);
    }
}

// Function to highlight Results nav item (called when results are available)
function highlightResultsNav() {
    console.log('Highlighting results navigation...');

    const resultsButton = document.getElementById('nav-results');
    if (resultsButton) {
        // Enable the button
        resultsButton.classList.remove('nav-btn-disabled');
        resultsButton.classList.add('nav-btn-enabled', 'nav-btn-highlight');

        // Add visual highlighting
        resultsButton.style.boxShadow = '0 0 10px rgba(59, 130, 246, 0.5)';
        resultsButton.style.transition = 'box-shadow 0.3s ease';

        // Remove highlight after 3 seconds
        setTimeout(() => {
            if (resultsButton) {
                resultsButton.style.boxShadow = '';
                resultsButton.classList.remove('nav-btn-highlight');
            }
        }, 3000);
    }

    // Update results card on dashboard if present
    const resultsCard = document.getElementById('results-card');
    const resultsCardStatus = document.getElementById('results-card-status');

    if (resultsCard) {
        resultsCard.classList.remove('opacity-50');
        resultsCard.classList.add('opacity-100');
        resultsCard.style.cursor = 'pointer';
    }

    if (resultsCardStatus) {
        resultsCardStatus.textContent = 'Results available - Click to view';
    }

    console.log('Results navigation highlighted successfully');
}

// Export functions for global access
window.showSection = showSection;
window.showResultsTab = showResultsTab;
window.handleResultsCardClick = handleResultsCardClick;
window.disableResultsNav = disableResultsNav;
window.enableResultsNav = enableResultsNav;
window.highlightResultsNav = highlightResultsNav;
window.initializeNavigation = initializeNavigation;
