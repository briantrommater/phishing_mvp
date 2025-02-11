async function analyzeText() {
    const text = document.getElementById("inputText").value;

    const response = await fetch("https://briantrommater.com/analyze", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ text })
    });

    const result = await response.json();
    document.getElementById("riskScore").innerText = result.risk_score + "% Risk";
}

// Ensure the page loads before running any scripts
document.addEventListener('DOMContentLoaded', () => {
    console.log("Phishing Detection Tool Loaded.");
});