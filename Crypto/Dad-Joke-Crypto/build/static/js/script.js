// Dad Jokes Database (unchanged)
const dadJokes = [
    "Why don't hackers get sick? Because they have anti-virus!",
    "Why did the cryptographer bring a ladder to work? He heard the security was going to be stepped up!",
    "What did the private key say to the public key? You complete me!",
    "Why did the hacker bring a blanket to the computer? Because it had a crypto cold!",
    "What's a cryptographer's favorite dance? The bit shuffle!",
    "Why did the encryption algorithm go to therapy? It had too many trust issues!",
    "What do you call a mathematician who can't handle cryptography? Probably not a prime candidate!",
    "Why did the RSA algorithm feel lonely? It couldn't find its prime companion!",
    "What's a hacker's favorite exercise? Cryptographic hash functions!",
    "Why did the cryptographer bring a dictionary to work? To look up cipher text!",
    "Why was the binary tree sad? All its root issues!",
    "What did the firewall say to the hacker? You shall not pass!",
    "Why do programmers hate nature? Too many bugs!",
    "What's a hacker's favorite season? Phishing season!",
    "Why did the cookie cry? Because its father was a wafer so long!",
    "What's a cryptographer's favorite movie? The DaVinci Code-r!",
    "Why did the SHA-256 feel confident? It was hash-ured of itself!",
    "What's a hacker's favorite drink? Root beer!",
    "Why did the SSL certificate go to therapy? Trust issues!",
    "What's a cryptographer's favorite band? The Rolling XORs!",
    "How do hackers stay warm? They use a firewall!",
    "What's a cryptographer's favorite food? Hash browns!",
    "Why did the DDOS attack go to the gym? To get buffer!",
    "What's a penetration tester's favorite game? Break the firewall!",
    "Why don't cryptographers like parties? Too many leaks!",
    "What did the bit say to the byte? You bit more than you can chew!",
    "Why was the blockchain developer broke? Lost all their bits in a hash collision!",
    "What's a hacker's favorite pizza? Pepperoni with extra bytes!",
    "Why did the computer go to the doctor? It had a bad case of the Trojans!",
    "What's a cryptographer's favorite dance move? The blockchain shuffle!",
    "Why did the null pointer feel lonely? It was pointing to nothing in life!",
    "What's a hacker's favorite car? A Cyber-truck!",
    "Why did the algorithm break up with the data structure? No hash tags!",
    "What's a cryptographer's favorite garden plant? Hash browns!",
    "Why did the packet get lost? It forgot its routing manners!"
];

// Loading Screen Handler
document.addEventListener('DOMContentLoaded', () => {
    setTimeout(() => {
        const loadingScreen = document.querySelector('.loading-screen');
        loadingScreen.classList.add('hidden');
    }, 1500);
    
    setupDadJokes();
    setupFormValidation();
    setupCodeHighlighting();
    setupNavigation();
});

// Dad Jokes Rotator
function setupDadJokes() {
    const dadJokeBanner = document.getElementById('randomDadJoke');
    if (dadJokeBanner) {
        setInterval(() => {
            const randomJoke = dadJokes[Math.floor(Math.random() * dadJokes.length)];
            dadJokeBanner.innerHTML = `<i class="fas fa-laugh-beam"></i> ${randomJoke}`;
            dadJokeBanner.style.opacity = '0';
            setTimeout(() => {
                dadJokeBanner.style.opacity = '1';
            }, 100);
        }, 10000);
        
        dadJokeBanner.innerHTML = `<i class="fas fa-laugh-beam"></i> ${dadJokes[0]}`;
    }
}

// Form Validation
function setupFormValidation() {
    const powForm = document.querySelector('form');
    if (powForm) {
        powForm.addEventListener('submit', (e) => {
            const solution = document.getElementById('solution').value;
            if (!solution.match(/^[a-z0-9]+$/)) {
                e.preventDefault();
                showNotification('Solution must contain only lowercase letters and numbers!', 'error');
            }
        });
    }
}

// Code Highlighting Animation
function setupCodeHighlighting() {
    const codeBlocks = document.querySelectorAll('pre code');
    codeBlocks.forEach(block => {
        const lines = block.innerHTML.split('\n');
        block.innerHTML = lines.map(line => 
            `<div class="code-line">${line}</div>`
        ).join('');
    });
}

// Navigation Active State
function setupNavigation() {
    const currentPath = window.location.pathname;
    const navLinks = document.querySelectorAll('.nav-link');
    navLinks.forEach(link => {
        if (link.getAttribute('href') === currentPath) {
            link.classList.add('active');
        }
    });
}

// Copy to Clipboard Function
function copyToClipboard(text) {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand('copy');
    document.body.removeChild(textarea);
    showNotification('Command copied to clipboard!', 'info');
}

// Notification System
function showNotification(message, type = 'info') {
    const notification = document.getElementById('notification');
    const notificationText = document.getElementById('notification-text');
    
    notification.className = `notification ${type}`;
    notificationText.textContent = message;
    notification.classList.add('show');
    
    setTimeout(() => {
        notification.classList.remove('show');
    }, 3000);
}

// Easter Egg
let konami = '';
const konamiCode = 'ArrowUpArrowUpArrowDownArrowDownArrowLeftArrowRightArrowLeftArrowRightba';
document.addEventListener('keydown', (e) => {
    konami += e.key;
    if (konami.length > konamiCode.length) {
        konami = konami.substring(1);
    }
    if (konami === konamiCode) {
        showNotification('🎉 You found the Easter egg! But the real treasure is the dad jokes we made along the way!');
    }
});
