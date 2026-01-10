// Get API URL from environment or default to local
const API_URL = window.API_URL || 'http://localhost:8000';

console.log('API URL:', API_URL);

async function scanUrl() {
    let urlInput = document.getElementById("urlInput");
    let resultBox = document.getElementById("result-box");
    let resultText = document.getElementById("result");
    let loading = document.getElementById("loading");

    let url = urlInput.value.trim();
    if (!url) {
        resultText.innerText = "⚠️ Please enter a valid URL!";
        resultBox.classList.remove("hidden");
        return;
    }

    loading.classList.remove("hidden");
    resultBox.classList.add("hidden");

    try {
        // Try API endpoint first, fallback to /scan/
        const endpoints = [
            `${API_URL}/api/scan?url=${encodeURIComponent(url)}`,
            `${API_URL}/scan/?url=${encodeURIComponent(url)}`
        ];

        let response;
        let data;
        let error;

        for (const endpoint of endpoints) {
            try {
                console.log('Trying endpoint:', endpoint);
                response = await fetch(endpoint);
                if (response.ok) {
                    data = await response.json();
                    console.log('Success with endpoint:', endpoint);
                    break;
                }
            } catch (e) {
                error = e;
                console.log('Failed with endpoint:', endpoint, e);
            }
        }

        if (!data) {
            throw error || new Error('All endpoints failed');
        }

        loading.classList.add("hidden");
        resultBox.classList.remove("hidden");

        if (data.status.includes("Suspicious")) {
            resultText.innerHTML = `❌ <span class="suspicious">${data.status}</span>`;
        } else {
            resultText.innerHTML = `✅ <span class="safe">${data.status}</span>`;
        }
    } catch (error) {
        console.error('Error:', error);
        loading.classList.add("hidden");
        resultText.innerText = "⚠️ Error scanning the URL. Make sure backend is running.";
        resultBox.classList.remove("hidden");
    }
}

/* Toggle Dark Mode */
function toggleTheme() {
    document.body.classList.toggle("dark-mode");
}
