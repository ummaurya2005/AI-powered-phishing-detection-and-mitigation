// Smooth fade-in animation
document.addEventListener("DOMContentLoaded", () => {
    document.querySelector(".container").classList.add("fade-in");
});

// Add a confirmation alert for block button
function confirmBlock(event) {
    const ok = confirm("⚠️ Are you sure?\nThis URL will be BLOCKED and added to blacklist permanently.");
    if (!ok) {
        event.preventDefault();
    }
}

// Add small delay animation for "Allow" button
function allowClick(event) {
    alert("✔ You chose to ALLOW this URL.\nProceeding...");
}
