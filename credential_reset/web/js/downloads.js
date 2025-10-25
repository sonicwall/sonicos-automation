// Download Functions for SonicWall Credential Reset Tool
// Handles file downloads and download error handling

// GLOBAL: Function to download individual export files - moved to global scope
async function downloadExportFile(category, fileKey, fileName) {
    const buttonId = `download-${category}-${fileKey}`;
    const button = document.getElementById(buttonId);

    if (!button) return;

    // Show loading state
    button.disabled = true;
    const originalContent = button.innerHTML;
    button.innerHTML = `
        <svg class="w-3 h-3 export-download-loading" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <circle cx="12" cy="12" r="10" stroke-dasharray="31.416" stroke-dashoffset="31.416" stroke-width="2" fill="none"/>
        </svg>
    `;

    try {
        console.log(`Downloading ${category} file: ${fileName}`);

        // Make API call to download the specific file
        const response = await fetch(`/download/${category}/${fileKey}`, {
            method: 'GET',
            headers: {
                'Accept': 'application/octet-stream',
            }
        });

        if (!response.ok) {
            throw new Error(`Download failed: ${response.status} ${response.statusText}`);
        }

        // Get the file blob
        const blob = await response.blob();

        // Create download link
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = fileName;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        console.log(`Successfully downloaded: ${fileName}`);

        // Reset button state after successful download
        button.disabled = false;
        button.innerHTML = originalContent;

    } catch (error) {
        console.error('Download failed:', error);

        // Show error state
        button.innerHTML = `
            <svg class="w-3 h-3 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z"></path>
            </svg>
            Error
        `;

        // Show error message
        alert(`Failed to download ${fileName}: ${error.message}`);

        // Reset button after delay
        setTimeout(() => {
            button.disabled = false;
            button.innerHTML = originalContent;
        }, 3000);
    }
}

// Function to initialize downloads functionality
function initializeDownloads() {
    console.log('Initializing downloads functionality...');

    // Set up any global download event listeners or configurations
    // This function can be extended as needed for download-specific initialization

    console.log('Downloads functionality initialized successfully');
}

// Export functions for global access
window.downloadExportFile = downloadExportFile;
window.initializeDownloads = initializeDownloads;
