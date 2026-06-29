# logAnalyzer.js
logAnalyzer.js A log analysis tool that parses authentication logs, counts failed login attempts per IP address, and flags potential brute-force sources that exceed a configurable threshold. Demonstrates pattern detection and basic intrusion-detection logic — the kind of failed-login analysis SOC analysts perform regularly.
// logAnalyzer.js
// Parses a log file and flags IPs with repeated failed login attempts.
// Useful for spotting brute-force patterns.

const fs = require("fs");

const THRESHOLD = 5; // flag IPs with this many or more failures

function analyzeLog(filePath) {
  let data;
  try {
    data = fs.readFileSync(filePath, "utf-8");
  } catch (err) {
    console.log(`Could not read file: ${filePath}`);
    return;
  }

  const lines = data.split("\n");
  const failedAttempts = {};

  // Matches lines containing "Failed password" and an IP address
  const ipRegex = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/;

  lines.forEach((line) => {
    if (line.toLowerCase().includes("failed password")) {
      const match = line.match(ipRegex);
      if (match) {
        const ip = match[1];
        failedAttempts[ip] = (failedAttempts[ip] || 0) + 1;
      }
    }
  });

  console.log("Failed login summary:\n");
  const flagged = [];
  for (const [ip, count] of Object.entries(failedAttempts)) {
    console.log(`${ip}: ${count} failed attempt(s)`);
    if (count >= THRESHOLD) flagged.push(ip);
  }

  if (flagged.length) {
    console.log(`\n⚠️  Suspicious IPs (>= ${THRESHOLD} failures):`);
    flagged.forEach((ip) => console.log(`  - ${ip}`));
  } else {
    console.log("\nNo suspicious activity detected.");
  }
}

const file = process.argv[2];
if (!file) {
  console.log("Usage: node logAnalyzer.js <logfile>");
  console.log("Example: node logAnalyzer.js auth.log");
} else {
  analyzeLog(file);
}
