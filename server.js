require("dotenv").config({ path: "ItsKey.env" }); // Load .env file
const express = require("express");
const axios = require("axios");
const cors = require("cors");

const app = express();
const PORT = 5000;

app.use(cors());
app.use(express.json());

// Load API keys from .env file
const SHODAN_API_KEY = process.env.SHODAN_API_KEY;
const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY;
const NUM_VERIFY_API_KEY=process.env.NUM_VERIFY_API_KEY;

if (!SHODAN_API_KEY || !VIRUSTOTAL_API_KEY) {
    console.error("❌ Missing API Keys in .env file. Please add SHODAN_API_KEY and VIRUSTOTAL_API_KEY.");
    process.exit(1); // Stop server if API keys are missing
}

// 🔍 IP Lookup with Shodan
app.get("/ip/:ip", async (req, res) => {
    try {
        const { ip } = req.params;
        console.log(`🔍 Received request for IP: ${ip}`);

        if (!ip) {
            console.error("❌ Error: IP parameter is missing.");
            return res.status(400).json({ error: "IP parameter is required." });
        }

        const url = `https://api.shodan.io/shodan/host/${ip}?key=${SHODAN_API_KEY}`;
        console.log(`🌐 Fetching IP details from Shodan: ${url}`);

        const response = await axios.get(url);
        console.log("✅ Shodan Response received:", response.data);

        res.json(response.data);
    } catch (error) {
        console.error("❌ Error occurred:", error.message);

        if (error.response) {
            console.error("🔴 API Error Response:", error.response.data);
            return res.status(error.response.status).json({ error: error.response.data });
        } else if (error.request) {
            console.error("🔴 No response received from Shodan API.");
            return res.status(500).json({ error: "No response from Shodan API." });
        } else {
            console.error("🔴 Unexpected Error:", error);
            return res.status(500).json({ error: "Internal server error." });
        }
    }
});






//domain lookup shodan
app.get("/whois/:domain", async (req, res) => {
    try {
        const { domain } = req.params;
        console.log(`🔍 Received request for domain: ${domain}`);

        if (!domain) {
            console.error("❌ Error: Domain parameter is missing.");
            return res.status(400).json({ error: "Domain parameter is required." });
        }
        //https://api.shodan.io/dns/domain/google.com?key=DHRKpOodJB4T6oDebePlCDmlkjwD9mrh
        const url = `https://api.shodan.io/dns/domain/${domain}?key=${SHODAN_API_KEY}`;
        console.log(`🌐 Fetching data from Shodan: ${url}`);

        const response = await axios.get(url);
        console.log("✅ Shodan Response received:", response.data);

        res.json(response.data);
    } catch (error) {
        console.error("❌ Error occurred:", error.message);

        if (error.response) {
            console.error("🔴 API Error Response:", error.response.data);
            return res.status(error.response.status).json({ error: error.response.data });
        } else if (error.request) {
            console.error("🔴 No response received from Shodan API.");
            return res.status(500).json({ error: "No response from Shodan API." });
        } else {
            console.error("🔴 Unexpected Error:", error);
            return res.status(500).json({ error: "Internal server error." });
        }
    }
});


app.get("/phone/:phone", async (req, res) => {
    try {
        const { phone } = req.params;
        console.log(`🔍 Received request for domain: ${phone}`);

        if (!phone) {
            console.error("❌ Error: Domain parameter is missing.");
            return res.status(400).json({ error: "Domain parameter is required." });
        }
        //https://apilayer.net/api/validate?access_key=YOUR_API_KEY&number=+1234567890
        const url = `https://apilayer.net/api/validate?access_key=${NUM_VERIFY_API_KEY}&number=${phone}`;
        console.log(`🌐 Fetching data from Shodan: ${url}`);

        const response = await axios.get(url);
        console.log("✅ Shodan Response received:", response.data);

        res.json(response.data);
    } catch (error) {
        console.error("❌ Error occurred:", error.message);

        if (error.response) {
            console.error("🔴 API Error Response:", error.response.data);
            return res.status(error.response.status).json({ error: error.response.data });
        } else if (error.request) {
            console.error("🔴 No response received from Shodan API.");
            return res.status(500).json({ error: "No response from Shodan API." });
        } else {
            console.error("🔴 Unexpected Error:", error);
            return res.status(500).json({ error: "Internal server error." });
        }
    }
});




app.get("/scan/:url", async (req, res) => {
    try {
        let { url } = req.params;
        url = decodeURIComponent(url); // Decode URL before processing
        console.log(`🔍 Received request to scan URL: ${url}`);

        if (!url) {
            console.error("❌ Error: URL parameter is missing.");
            return res.status(400).json({ error: "URL parameter is required." });
        }

        // 1️⃣ Submit URL to VirusTotal
        const submitResponse = await axios.post(
            "https://www.virustotal.com/api/v3/urls",
            new URLSearchParams({ url }), // No need to encode again
            {
                headers: {
                    "x-apikey": VIRUSTOTAL_API_KEY,
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            }
        );

        const urlId = submitResponse.data.data.id;
        console.log(`🌐 Submitted URL. VirusTotal ID: ${urlId}`);

        // 2️⃣ **Wait for VirusTotal to process the scan**
        console.log("⏳ Waiting for VirusTotal to analyze the URL...");
        await new Promise(resolve => setTimeout(resolve, 10000)); // Wait 10 seconds

        // 3️⃣ Fetch the analysis report
        const reportResponse = await axios.get(
            `https://www.virustotal.com/api/v3/analyses/${urlId}`,
            {
                headers: { "x-apikey": VIRUSTOTAL_API_KEY },
            }
        );

        console.log("✅ VirusTotal Scan Report received:", reportResponse.data);
        res.json(reportResponse.data);
    } catch (error) {
        console.error("❌ Error occurred:", error.message);

        if (error.response) {
            console.error("🔴 API Error Response:", error.response.data);
            return res.status(error.response.status).json({ error: error.response.data });
        } else if (error.request) {
            console.error("🔴 No response received from VirusTotal API.");
            return res.status(500).json({ error: "No response from VirusTotal API." });
        } else {
            console.error("🔴 Unexpected Error:", error);
            return res.status(500).json({ error: "Internal server error." });
        }
    }
});






app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
});


