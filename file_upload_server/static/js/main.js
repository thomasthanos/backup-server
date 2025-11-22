// File Upload Handler
const uploadArea = document.getElementById('uploadArea');
const fileInput = document.getElementById('fileInput');
const progressContainer = document.getElementById('progressContainer');
const progressFill = document.getElementById('progressFill');
const progressText = document.getElementById('progressText');

// Modal Elements
const modalOverlay = document.getElementById('modalOverlay');
const modalMessage = document.getElementById('modalMessage');
const modalOk = document.getElementById('modalOk');
const modalCancel = document.getElementById('modalCancel');

/**
 * Display a custom modal dialog.
 * @param {string} message - The message to display in the modal.
 * @param {boolean} showCancel - Whether to show the cancel button (used for confirmations).
 * @param {function} [onOk] - Callback executed when OK is pressed.
 */
function showModal(message, showCancel, onOk) {
    if (!modalOverlay || !modalMessage || !modalOk || !modalCancel) return;
    modalMessage.textContent = message;
    // Show or hide the cancel button based on whether this is a confirm or alert
    if (showCancel) {
        modalCancel.style.display = 'inline-block';
    } else {
        modalCancel.style.display = 'none';
    }
    // Remove any existing handlers to avoid stacking
    const cleanHandlers = () => {
        modalOk.onclick = null;
        modalCancel.onclick = null;
    };
    // Handler for OK
    modalOk.onclick = () => {
        modalOverlay.style.display = 'none';
        cleanHandlers();
        if (typeof onOk === 'function') {
            onOk();
        }
    };
    // Handler for Cancel simply hides the modal
    modalCancel.onclick = () => {
        modalOverlay.style.display = 'none';
        cleanHandlers();
    };
    // Display the modal
    modalOverlay.style.display = 'flex';
}

/**
 * Show an alert modal with an OK button.
 * @param {string} message
 */
function showAlert(message) {
    showModal(message, false);
}

/**
 * Show a confirmation modal with OK and Cancel buttons.
 * @param {string} message
 * @param {function} onConfirm - Callback executed if the user confirms.
 */
function showConfirm(message, onConfirm) {
    showModal(message, true, onConfirm);
}

if (uploadArea) {
    // Click to upload
    uploadArea.addEventListener('click', () => {
        fileInput.click();
    });

    // Drag and drop
    uploadArea.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadArea.classList.add('dragover');
    });

    uploadArea.addEventListener('dragleave', () => {
        uploadArea.classList.remove('dragover');
    });

    uploadArea.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadArea.classList.remove('dragover');
        
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            handleFileUpload(files[0]);
        }
    });

    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            handleFileUpload(e.target.files[0]);
        }
    });
}

function handleFileUpload(file) {
    // Determine whether to perform a normal upload or a chunked upload.
    // Cloudflare (and similar proxies) impose a hard limit on request sizes (e.g., 100 MB).
    // If the file exceeds a configurable threshold, upload it in smaller chunks
    // so that each request stays under the limit. Once all chunks have been
    // uploaded, the server assembles them into the final file.

    const MAX_CHUNK_SIZE = 50 * 1024 * 1024; // 50 MB per chunk; safely below the 100 MB proxy limit

    // Use chunked upload if the file exceeds our chunk size
    if (file.size > MAX_CHUNK_SIZE) {
        uploadLargeFile(file, MAX_CHUNK_SIZE);
        return;
    }

    // Otherwise, proceed with a standard single request upload
    const formData = new FormData();
    formData.append('file', file);
    // Add folder_id if we're inside a folder
    if (typeof currentFolderId !== 'undefined' && currentFolderId !== null) {
        formData.append('folder_id', currentFolderId);
    }
    // Show progress
    progressContainer.style.display = 'block';
    progressFill.style.width = '0%';
    progressText.textContent = 'Uploading...';
    const xhr = new XMLHttpRequest();
    // Progress tracking
    xhr.upload.addEventListener('progress', (e) => {
        if (e.lengthComputable) {
            const percentComplete = (e.loaded / e.total) * 100;
            progressFill.style.width = percentComplete + '%';
            progressText.textContent = `Uploading: ${Math.round(percentComplete)}%`;
        }
    });
    // Upload complete
    xhr.addEventListener('load', () => {
        if (xhr.status === 200) {
            progressText.textContent = 'Upload complete! Refreshing...';
            progressFill.style.width = '100%';
            setTimeout(() => {
                window.location.reload();
            }, 1000);
        } else {
            progressText.textContent = 'Upload failed!';
            progressFill.style.width = '0%';
            showAlert('Upload failed. Please try again.');
            progressContainer.style.display = 'none';
        }
    });
    // Error handling
    xhr.addEventListener('error', () => {
        progressText.textContent = 'Upload failed!';
        showAlert('Upload failed. Please check your connection.');
        progressContainer.style.display = 'none';
    });
    xhr.open('POST', '/upload');
    xhr.send(formData);
}

/**
 * Upload a file in multiple chunks. Each chunk is sent sequentially to
 * the server via the /upload endpoint with metadata describing its
 * position within the sequence. After the last chunk uploads, the
 * server assembles them into a final file. Progress is displayed
 * proportionally to the number of chunks completed.
 *
 * @param {File} file - The file to upload.
 * @param {number} chunkSize - The maximum size of each chunk in bytes.
 */
function uploadLargeFile(file, chunkSize) {
    const totalChunks = Math.ceil(file.size / chunkSize);
    const uploadId = `${Date.now()}-${Math.random().toString(36).substring(2, 10)}`;
    let currentChunk = 0;
    // Show progress bar for chunked uploads
    progressContainer.style.display = 'block';
    progressFill.style.width = '0%';
    progressText.textContent = 'Uploading...';
    /**
     * Upload the next chunk. This function is called recursively until all
     * chunks have been sent. On completion of the final chunk, the page
     * refreshes to show the newly uploaded file.
     */
    function uploadNextChunk() {
        const start = currentChunk * chunkSize;
        const end = Math.min(start + chunkSize, file.size);
        const blob = file.slice(start, end);
        const formData = new FormData();
        formData.append('file', blob);
        formData.append('chunk_index', currentChunk);
        formData.append('total_chunks', totalChunks);
        formData.append('file_name', file.name);
        formData.append('upload_id', uploadId);
        // Add folder_id if we're inside a folder
        if (typeof currentFolderId !== 'undefined' && currentFolderId !== null) {
            formData.append('folder_id', currentFolderId);
        }
        const xhr = new XMLHttpRequest();
        xhr.open('POST', '/upload');
        xhr.onload = function () {
            if (xhr.status === 200) {
                currentChunk++;
                // Update progress based on chunks completed
                const percent = (currentChunk / totalChunks) * 100;
                progressFill.style.width = percent + '%';
                progressText.textContent = `Uploading: ${Math.round(percent)}%`;
                if (currentChunk < totalChunks) {
                    uploadNextChunk();
                } else {
                    // All chunks uploaded, refresh page after brief delay
                    progressText.textContent = 'Upload complete! Refreshing...';
                    progressFill.style.width = '100%';
                    setTimeout(() => {
                        window.location.reload();
                    }, 1000);
                }
            } else {
                progressText.textContent = 'Upload failed!';
                progressFill.style.width = '0%';
                showAlert('Upload failed. Please try again.');
                progressContainer.style.display = 'none';
            }
        };
        xhr.onerror = function () {
            progressText.textContent = 'Upload failed!';
            showAlert('Upload failed. Please check your connection.');
            progressContainer.style.display = 'none';
        };
        xhr.send(formData);
    }
    uploadNextChunk();
}

// Create folder handler
function createFolder() {
    const folderName = document.getElementById('folderNameInput').value.trim();
    
    if (!folderName) {
        // Use custom alert modal for empty folder name
        showAlert('Please enter a folder name');
        return;
    }

    const formData = new FormData();
    formData.append('folder_name', folderName);
    
    // Add parent_id if we're inside a folder
    if (typeof currentFolderId !== 'undefined' && currentFolderId !== null) {
        formData.append('parent_id', currentFolderId);
    }

    fetch('/create_folder', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            window.location.reload();
        } else {
            // Show error in custom modal
            showAlert('Failed to create folder: ' + (data.error || 'Unknown error'));
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showAlert('Failed to create folder');
    });
}

// Delete file handler
function deleteFile(fileId) {
    // Display confirmation modal before deleting a file
    showConfirm('Are you sure you want to delete this file?', () => {
        fetch(`/delete/${fileId}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        }
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                window.location.reload();
            } else {
                showAlert('Failed to delete file: ' + (data.error || 'Unknown error'));
            }
        })
        .catch(error => {
            console.error('Error:', error);
            showAlert('Failed to delete file');
        });
    });
}

// Delete folder handler
function deleteFolder(folderId) {
    // Display confirmation modal before deleting a folder
    showConfirm('Are you sure you want to delete this folder? It must be empty.', () => {
        fetch(`/delete_folder/${folderId}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        }
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                window.location.reload();
            } else {
                showAlert('Failed to delete folder: ' + (data.error || 'Folder must be empty'));
            }
        })
        .catch(error => {
            console.error('Error:', error);
            showAlert('Failed to delete folder');
        });
    });
}

// Format file size
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

// Auto-dismiss alerts
setTimeout(() => {
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(alert => {
        alert.style.transition = 'opacity 0.5s ease';
        alert.style.opacity = '0';
        setTimeout(() => alert.remove(), 500);
    });
}, 5000);

// Prevent form resubmission on page refresh
if (window.history.replaceState) {
    window.history.replaceState(null, null, window.location.href);
}

// Enter key to create folder
document.addEventListener('DOMContentLoaded', () => {
    const folderInput = document.getElementById('folderNameInput');
    if (folderInput) {
        folderInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                createFolder();
            }
        });
    }
});
