async function startScan() {
    const targetUrl = document.getElementById('target-url').value;
    if (!targetUrl) {
        alert('Please enter a target URL');
        return;
    }

    try {
        const response = await fetch('http://localhost:5000/api/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ target_url: targetUrl })
        });

        const data = await response.json();

        if (response.ok) {
            alert(data.message);
            fetchResults();
        } else {
            alert(data.error);
        }
    } catch (error) {
        console.error('Error:', error);
        alert('An error occurred. Please try again.');
    }
}

async function fetchResults() {
    try {
        const response = await fetch('http://localhost:5000/api/results');
        const data = await response.json();

        const resultsTable = document.getElementById('results-table').querySelector('tbody');
        resultsTable.innerHTML = '';

        data.forEach(result => {
            const row = document.createElement('tr');

            Object.keys(result).forEach(key => {
                const cell = document.createElement('td');
                cell.textContent = result[key];
                row.appendChild(cell);
            });

            resultsTable.appendChild(row);
        });
    } catch (error) {
        console.error('Error:', error);
        alert('Failed to fetch scan results.');
    }
}

document.addEventListener('DOMContentLoaded', fetchResults);

