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

    // If the file qualifies for a chunked upload, we also check if there's
    // an existing incomplete upload in localStorage. If found and it matches
    // this file, resume from where we left off. This enables continued
    // uploading after network interruptions or browser restarts as long as
    // the user selects the same file again.
    if (file.size > MAX_CHUNK_SIZE) {
        try {
            const stateJson = localStorage.getItem('uploadState');
            let state = null;
            if (stateJson) {
                state = JSON.parse(stateJson);
            }
            if (state && state.fileName === file.name && state.fileSize === file.size) {
                // Prompt the user to resume the upload
                showConfirm('An incomplete upload was detected for this file. Do you want to resume?', () => {
                    uploadLargeFile(file, MAX_CHUNK_SIZE, state);
                });
                return;
            }
        } catch (e) {
            console.warn('Error parsing upload state:', e);
        }
        // No saved state, start a new chunked upload
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
    // If the admin has selected the public toggle, include a flag so the server
    // marks the upload as public.  The admin flag is determined on the server
    // side; here we just send the field if the checkbox exists and is checked.
    const publicCheckbox = document.getElementById('publicCheckbox');
    if (publicCheckbox && publicCheckbox.checked) {
        formData.append('public', '1');
    }
    // Show progress
    progressContainer.style.display = 'block';
    progressFill.style.width = '0%';
    progressText.textContent = 'Uploading...';
    // Record the start time for speed calculations
    const startTime = Date.now();
    const xhr = new XMLHttpRequest();
    // Progress tracking
    xhr.upload.addEventListener('progress', (e) => {
        if (e.lengthComputable) {
            const percentComplete = (e.loaded / e.total) * 100;
            // Calculate upload speed in bytes per second
            const elapsedSeconds = (Date.now() - startTime) / 1000;
            // Guard against divide by zero if progress event fires immediately
            const speedBps = elapsedSeconds > 0 ? e.loaded / elapsedSeconds : 0;
            // Convert to human readable units (KB/s or MB/s)
            let speedText;
            if (speedBps > 1024 * 1024) {
                speedText = (speedBps / (1024 * 1024)).toFixed(2) + ' MB/s';
            } else if (speedBps > 1024) {
                speedText = (speedBps / 1024).toFixed(2) + ' KB/s';
            } else {
                speedText = speedBps.toFixed(2) + ' B/s';
            }
            progressFill.style.width = percentComplete + '%';
            progressText.textContent = `Uploading: ${Math.round(percentComplete)}% \u2013 ${speedText}`;
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
function uploadLargeFile(file, chunkSize, resumeState = null) {
    // Determine initial state. For resumed uploads we reuse the upload ID,
    // starting chunk index and totalChunks recorded previously. Otherwise we
    // generate a new upload ID and compute the total number of chunks.
    const totalChunks = resumeState && resumeState.totalChunks ? resumeState.totalChunks : Math.ceil(file.size / chunkSize);
    const uploadId = resumeState && resumeState.uploadId ? resumeState.uploadId : `${Date.now()}-${Math.random().toString(36).substring(2, 10)}`;
    let currentChunk = resumeState && typeof resumeState.currentChunk === 'number' ? resumeState.currentChunk : 0;
    // Show progress bar for chunked uploads
    progressContainer.style.display = 'block';
    progressFill.style.width = '0%';
    progressText.textContent = 'Uploading...';
    // Track start time to calculate upload speed across chunks
    const startTime = Date.now();
    // Maximum number of retries per chunk
    const MAX_RETRIES = 3;
    let retryCount = 0;
    // Save the upload state to localStorage to allow resuming. We update
    // currentChunk after each successful chunk upload.
    function saveState() {
        const state = {
            fileName: file.name,
            fileSize: file.size,
            uploadId: uploadId,
            currentChunk: currentChunk,
            totalChunks: totalChunks,
            chunkSize: chunkSize
        };
        try {
            localStorage.setItem('uploadState', JSON.stringify(state));
        } catch (e) {
            // If localStorage quota is exceeded or disabled, silently ignore
            console.warn('Could not save upload state:', e);
        }
    }
    /**
     * Upload the next chunk. This function is called recursively until all
     * chunks have been sent. On completion of the final chunk, the page
     * refreshes to show the newly uploaded file. If a chunk fails, it will
     * retry up to MAX_RETRIES times. State is persisted to localStorage
     * between chunk uploads so that the upload can be resumed if necessary.
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
        // Include the public flag if the admin selected the public toggle.  The
        // server will ignore this for non-admin users.
        const publicCheckbox = document.getElementById('publicCheckbox');
        if (publicCheckbox && publicCheckbox.checked) {
            formData.append('public', '1');
        }
        const xhr = new XMLHttpRequest();
        xhr.open('POST', '/upload');
        // Track per‑chunk progress to compute speed
        xhr.upload.addEventListener('progress', (e) => {
            if (e.lengthComputable) {
                // Bytes uploaded so far across all chunks
                const uploadedBytes = currentChunk * chunkSize + e.loaded;
                const percent = (uploadedBytes / file.size) * 100;
                const elapsedSeconds = (Date.now() - startTime) / 1000;
                const speedBps = elapsedSeconds > 0 ? uploadedBytes / elapsedSeconds : 0;
                let speedText;
                if (speedBps > 1024 * 1024) {
                    speedText = (speedBps / (1024 * 1024)).toFixed(2) + ' MB/s';
                } else if (speedBps > 1024) {
                    speedText = (speedBps / 1024).toFixed(2) + ' KB/s';
                } else {
                    speedText = speedBps.toFixed(2) + ' B/s';
                }
                progressFill.style.width = percent + '%';
                progressText.textContent = `Uploading: ${Math.round(percent)}% \u2013 ${speedText}`;
            }
        });
        xhr.onload = function () {
            if (xhr.status === 200) {
                retryCount = 0; // reset retry counter on success
                currentChunk++;
                // Persist state so we can resume later
                saveState();
                // Update progress based on chunks completed
                const percent = (currentChunk / totalChunks) * 100;
                progressFill.style.width = percent + '%';
                // Only update text here if not updated by progress event
                progressText.textContent = `Uploading: ${Math.round(percent)}%`;
                if (currentChunk < totalChunks) {
                    uploadNextChunk();
                } else {
                    // All chunks uploaded, remove saved state and refresh page after brief delay
                    try {
                        localStorage.removeItem('uploadState');
                    } catch (e) {
                        // ignore errors removing state
                    }
                    progressText.textContent = 'Upload complete! Refreshing...';
                    progressFill.style.width = '100%';
                    setTimeout(() => {
                        window.location.reload();
                    }, 1000);
                }
            } else {
                // On server error, attempt to retry the same chunk
                if (retryCount < MAX_RETRIES) {
                    retryCount++;
                    setTimeout(uploadNextChunk, 1000);
                } else {
                    progressText.textContent = 'Upload failed!';
                    progressFill.style.width = '0%';
                    showAlert('Upload failed. Please try again.');
                    progressContainer.style.display = 'none';
                }
            }
        };
        xhr.onerror = function () {
            // On network error, attempt to retry the same chunk up to MAX_RETRIES
            if (retryCount < MAX_RETRIES) {
                retryCount++;
                setTimeout(uploadNextChunk, 1000);
            } else {
                progressText.textContent = 'Upload failed!';
                showAlert('Upload failed. Please check your connection.');
                progressContainer.style.display = 'none';
            }
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

//
// Public toggle handler
//
// Administrators can mark a private file as public by clicking the 🌍 button
// on the dashboard. This function uses a confirmation modal before sending
// a POST request to /make_public/<file_id>. On success it reloads the page to
// reflect the updated access control. Any server error will be surfaced to
// the user through the alert modal.
function makePublic(fileId) {
    // Use our custom confirm modal to ask the admin for confirmation
    showConfirm('Are you sure you want to make this file public?', () => {
        fetch(`/make_public/${fileId}`, {
            method: 'POST'
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // The file was successfully marked as public. Refresh the page
                    // so the user can see the updated status and remove the public
                    // button for this entry.
                    window.location.reload();
                } else {
                    // Display any error returned by the server
                    const errorMsg = data.error || 'Failed to update file';
                    showAlert(errorMsg);
                }
            })
            .catch(error => {
                console.error('Error making file public:', error);
                showAlert('Failed to update file');
            });
    });
}