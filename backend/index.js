import express from "express"
import dotenv from "dotenv"
import cors from "cors"
import cookieParser from "cookie-parser";
import axios from "axios";
const app=express();
dotenv.config({
    path:"./.env"
})



var corsOptions = {
    origin: "*",
     methods:[ 'GET, POST, PUT, DELETE, OPTIONS'],
     credentials:true,
    optionsSuccessStatus: 200 // some legacy browsers (IE11, various SmartTVs) choke on 204
  }
  

app.use(cors(corsOptions))


app.use(express.json({limit:"16kb"}))
app.use(express.urlencoded({extended:true}))
app.use(express.static("public"))
app.use(cookieParser())


// app.get("/api/v1/getApiKey",()=>{
//   const API
// })



// VirusTotal API base URL
const VIRUSTOTAL_BASE_URL = 'https://www.virustotal.com/api/v3';

app.get('/api/v1/ip/:ip', async (req, res) => {
    const ipAddress = req.params.ip;
    
    
    try {
        const response = await axios.get(`${VIRUSTOTAL_BASE_URL}/ip_addresses/${ipAddress}`, {
            headers: {
                'x-apikey': "92e53797aab0fd4859e1fdba2c9522c64df0e444773a84a95ec9fad9c690a5d4"
            }
        });
        
        
        res.json(response.data);
    } catch (error) {
        console.error('Error fetching VirusTotal data:', error.message);
        res.status(500).json({ error: 'Failed to fetch VirusTotal data.' });
    }
});


// SHODAN base URL
const SHODAN_BASE_URL = 'https://api.shodan.io/shodan/host';

app.get('/api/v1/shodan/:ip', async (req, res) => {
  const ip = req.params.ip;
  
  const apiKey = "sA2TCxYkTNJa21dlOvNg5rloqTmxa5lU";

  try {
    const response = await axios.get(`${SHODAN_BASE_URL}/${ip}?key=${apiKey}`);
    res.json(response.data);
  } catch (error) {
    console.error('Error fetching Shodan data:', error.response?.data || error.message);
    res.status(error.response?.status || 500).json({
      error: 'Failed to fetch Shodan data.',
      details: error.response?.data || error.message,
    });
  }
});


//vulns api
const NVD_BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

app.get('/api/v1/cves', async (req, res) => {
  const keyword = req.query.keyword;
  console.log(keyword);
  

  if (!keyword) {
    return res.status(400).json({ error: 'Keyword is required' });
  }

  try {
    const response = await axios.get(NVD_BASE_URL, {
      params: {
        keywordSearch: keyword,
      },
      headers: {
        // Optional: Add API Key if you have one
        // 'apiKey': process.env.NVD_API_KEY,
      },
    });

    res.json(response.data);
  } catch (error) {
    console.error('Error fetching NVD data:', error.response?.data || error.message);
    res.status(500).json({ error: 'Failed to fetch CVE data' });
  }
});












const API_BASE_URL = process.env.API_BASE_URL || 'http://localhost:8000'

app.listen(process.env.PORT || 8000,()=>{
    console.log(`server is listening to the port ${API_BASE_URL}`)
})
app.get("/",(req,res)=>{
    res.send("Server is ready")
})

