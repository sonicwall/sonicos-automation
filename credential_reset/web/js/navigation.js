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
    const usersTab = document.getElementById('tab-users');
    const reportTab = document.getElementById('tab-report');

    if (summaryTab) {
        summaryTab.addEventListener('click', () => showResultsTab('summary'));
    }

    if (usersTab) {
        usersTab.addEventListener('click', (event) => {
            try {
                console.log('Users tab clicked, checking if enabled...');
                // Only allow clicking if tab is not disabled
                if (!usersTab.disabled) {
                    console.log('Users tab is enabled, switching to users tab');
                    showResultsTab('users');
                } else {
                    console.log('Users tab is disabled, click ignored');
                    event.preventDefault();
                }
            } catch (error) {
                console.error('Error handling users tab click:', error);
                event.preventDefault();
            }
        });
    }

    if (reportTab) {
        reportTab.addEventListener('click', () => showResultsTab('report'));
    }

    console.log('Results tabs event listeners setup complete');
}

// Function to show specific results tab
function showResultsTab(tabName) {
    console.log(`Switching to ${tabName} tab`);

    try {
        // Get all tab elements
        const summaryTab = document.getElementById('tab-summary');
        const usersTab = document.getElementById('tab-users');
        const reportTab = document.getElementById('tab-report');

        // Get all content elements
        const summaryContent = document.getElementById('tab-content-summary');
        const usersContent = document.getElementById('tab-content-users');
        const reportContent = document.getElementById('tab-content-report');

        // Check if users tab is disabled and prevent switching to it
        if (tabName === 'users' && usersTab && usersTab.disabled) {
            console.log('Cannot switch to users tab - it is disabled');
            return;
        }

    // Reset all tabs to inactive state
    const tabs = [summaryTab, usersTab, reportTab];
    tabs.forEach(tab => {
        if (tab) {
            tab.classList.remove('tab-active', 'border-blue-500', 'text-blue-600', 'border-orange-500', 'text-orange-600');
            tab.classList.add('tab-inactive', 'border-transparent', 'text-gray-500');
        }
    });

    // Hide all content
    const contents = [summaryContent, usersContent, reportContent];
    contents.forEach(content => {
        if (content) {
            content.classList.remove('show');
            content.classList.add('hide');
        }
    });

    // Activate the selected tab and show its content
    switch (tabName) {
        case 'summary':
            if (summaryTab && summaryContent) {
                summaryTab.classList.remove('tab-inactive', 'border-transparent', 'text-gray-500');
                summaryTab.classList.add('tab-active', 'border-orange-500', 'text-orange-600');
                summaryContent.classList.remove('hide');
                summaryContent.classList.add('show');
            }
            break;
        case 'users':
            if (usersTab && usersContent) {
                usersTab.classList.remove('tab-inactive', 'border-transparent', 'text-gray-500');
                usersTab.classList.add('tab-active', 'border-blue-500', 'text-blue-600');
                usersContent.classList.remove('hide');
                usersContent.classList.add('show');
            }
            break;
        case 'report':
            if (reportTab && reportContent) {
                reportTab.classList.remove('tab-inactive', 'border-transparent', 'text-gray-500');
                reportTab.classList.add('tab-active', 'border-blue-500', 'text-blue-600');
                reportContent.classList.remove('hide');
                reportContent.classList.add('show');
            }
            break;
        default:
            console.warn(`Unknown tab name: ${tabName}`);
            // Default to summary tab
            if (summaryTab && summaryContent) {
                summaryTab.classList.remove('tab-inactive', 'border-transparent', 'text-gray-500');
                summaryTab.classList.add('tab-active', 'border-orange-500', 'text-orange-600');
                summaryContent.classList.remove('hide');
                summaryContent.classList.add('show');
            }
    }

    console.log(`Tab switch to ${tabName} completed`);

    } catch (error) {
        console.error(`Error switching to ${tabName} tab:`, error);
        // Fallback to summary tab on error
        const summaryTab = document.getElementById('tab-summary');
        const summaryContent = document.getElementById('tab-content-summary');
        if (summaryTab && summaryContent) {
            summaryTab.classList.remove('tab-inactive', 'border-transparent', 'text-gray-500');
            summaryTab.classList.add('tab-active', 'border-orange-500', 'text-orange-600');
            summaryContent.classList.remove('hide');
            summaryContent.classList.add('show');
        }
    }
}

// Function to initialize help section features
function initializeHelpFeatures() {
    console.log('Initializing help section features...');

    // Handle markdown rendering if needed
    const markdownElements = document.querySelectorAll('[data-markdown]');
    markdownElements.forEach(element => {
        if (typeof marked !== 'undefined') {
            element.innerHTML = marked.parse(element.textContent);
        }
    });

    // Initialize collapsible sections
    initializeCollapsibles();
}

// Function to initialize collapsible sections
function initializeCollapsibles() {
    console.log('Initializing collapsibles...');

    // Define the toggle function globally if not already defined
    if (typeof window.toggleCollapsible !== 'function') {
        window.toggleCollapsible = function(button) {
            const content = button.nextElementSibling;
            if (!content) {
                console.log('No content element found for collapsible');
                return;
            }

            const isHidden = content.classList.contains('hidden');
            console.log('Toggle collapsible:', isHidden ? 'showing' : 'hiding');

            if (isHidden) {
                content.classList.remove('hidden');
                button.textContent = button.textContent.replace('▼', '▲');
            } else {
                content.classList.add('hidden');
                button.textContent = button.textContent.replace('▲', '▼');
            }
        };
    }

    // Find all collapsible buttons and ensure their content is hidden initially
    const collapsibleButtons = document.querySelectorAll('button[onclick*="toggleCollapsible"]');
    console.log('Found', collapsibleButtons.length, 'collapsible buttons');

    collapsibleButtons.forEach((button, index) => {
        const content = button.nextElementSibling;
        if (content) {
            // Ensure content starts hidden
            if (!content.classList.contains('hidden')) {
                content.classList.add('hidden');
                console.log('Initialized collapsible', index, 'as hidden');
            }

            // Ensure button shows the correct arrow
            if (!button.textContent.includes('▼') && !button.textContent.includes('▲')) {
                button.textContent = button.textContent + ' ▼';
            } else if (button.textContent.includes('▲')) {
                button.textContent = button.textContent.replace('▲', '▼');
            }
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

// Function to enable the users tab
function enableUsersTab() {
    console.log('Enabling users tab...');

    const usersTab = document.getElementById('tab-users');
    if (usersTab) {
        // Remove the disabled attribute - this will automatically make disabled: classes inactive
        usersTab.disabled = false;

        // Add hover effects that were suppressed by disabled state
        usersTab.classList.add('hover:text-gray-700');

        // Make the button cursor pointer when enabled
        usersTab.style.cursor = 'pointer';

        console.log('Users tab enabled successfully');
    } else {
        console.warn('Users tab element not found');
    }
}

// Function to disable the users tab
function disableUsersTab() {
    console.log('Disabling users tab...');

    const usersTab = document.getElementById('tab-users');
    if (usersTab) {
        // Set the disabled attribute - this will automatically activate disabled: classes
        usersTab.disabled = true;

        // Remove hover effects
        usersTab.classList.remove('hover:text-gray-700');

        // Reset cursor style
        usersTab.style.cursor = '';

        // If currently active, switch to summary tab
        if (usersTab.classList.contains('tab-active')) {
            showResultsTab('summary');
        }

        console.log('Users tab disabled successfully');
    } else {
        console.warn('Users tab element not found');
    }
}

// Function to populate users tab with data
function populateUsersTab(usersData) {
    console.log('Populating users tab with data...', usersData);

    // Declare usersTableContainer in function scope so it's available throughout
    const usersTableContainer = document.getElementById('users-table-container');

    try {
        if (!usersTableContainer) {
            console.error('Users table container not found');
            return;
        }

        if (!usersData || !Array.isArray(usersData) || usersData.length === 0) {
            console.log('No valid users data provided, showing empty state');
            usersTableContainer.innerHTML = `
                <div class="text-center py-8">
                    <p class="text-gray-500 italic">No user data available.</p>
                </div>
            `;
            disableUsersTab();
            return;
        }
    } catch (error) {
        console.error('Error in populateUsersTab:', error);
        // Show error state
        if (usersTableContainer) {
            usersTableContainer.innerHTML = `
                <div class="text-center py-8">
                    <p class="text-red-500 italic">Error loading user data.</p>
                </div>
            `;
        }
        disableUsersTab();
        return;
    }

    // Enable the users tab since we have data
    enableUsersTab();

    // Create users table
    let tableHTML = `
        <div class="overflow-x-auto">
            <table class="min-w-full divide-y divide-gray-200">
                <thead class="bg-gray-50">
                    <tr>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">User</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Forced Pwd Change</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Pwd Change Skipped</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">TOTP Reset Attempted</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">TOTP Reset Skipped</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">New Pwd</th>
                    </tr>
                </thead>
                <tbody class="bg-white divide-y divide-gray-200">
    `;

    usersData.forEach((user, index) => {
        const statusClass = user.status === 'active' ? 'text-green-600 bg-green-100' : 'text-red-600 bg-red-100';
        const rowClass = index % 2 === 0 ? 'bg-white' : 'bg-gray-50';

        tableHTML += `
            <tr class="${rowClass}">
                <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                    ${escapeHtml(user.name || 'N/A')}
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    ${user.forced_password_change ? 
                        '<span class="text-green-600">✓ Yes</span>' : 
                        '<span class="text-red-600">No</span>'
                    }
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    ${user.skipped
                        ? `<span class="text-red-600">Skipped<br>(${user.reason})</span>`
                        : `<span class="text-green-600">✓ Not Skipped</span>`
                    }
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    ${user.totp_unbind_attempted ? 
                        '<span class="text-gray-600">Yes</span>' : 
                        '<span class="text-gray-600">No</span>'
                    }
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                  ${user.totp_skipped 
                    ? `<span class="text-red-600">Skipped<br>(${user.totp_reason})</span>` 
                    : `<span class="text-green-600">✓ Not Skipped</span>`
                  }
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                  ${user.new_password
                      ? `<button class="ml-2 px-2 py-1 bg-blue-500 text-white text-xs rounded copy-btn"
                          data-password="${escapeHtml(user.new_password || '')}">
                          Copy
                        </button>
                        <span class="text-gray-600">${escapeHtml(user.new_password || '')}</span>`
                      : `<span class="text-gray-600"></span>`
                  }
                </td>
            </tr>
        `;
    });

    tableHTML += `
                </tbody>
            </table>
        </div>
        <div class="mt-4 text-sm text-gray-600">
            <p>Total users: ${usersData.length}</p>
        </div>
    `;

    usersTableContainer.innerHTML = tableHTML;
    console.log('Users tab populated successfully');
}

// Helper function to escape HTML
function escapeHtml(unsafe) {
    if (typeof unsafe !== 'string') {
        return String(unsafe);
    }
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// Export functions for global access
window.showSection = showSection;
window.showResultsTab = showResultsTab;
window.handleResultsCardClick = handleResultsCardClick;
window.disableResultsNav = disableResultsNav;
window.enableResultsNav = enableResultsNav;
window.initializeNavigation = initializeNavigation;
window.enableUsersTab = enableUsersTab;
window.disableUsersTab = disableUsersTab;
window.populateUsersTab = populateUsersTab;
window.setupResultsTabs = setupResultsTabs;
