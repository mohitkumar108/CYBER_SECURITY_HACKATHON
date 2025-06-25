import React, { createContext, useContext, useState, useCallback } from 'react';
import axios from 'axios';

const ApiContext = createContext();

export const useApi = () => {
  const context = useContext(ApiContext);
  if (!context) {
    throw new Error('useApi must be used within an ApiProvider');
  }
  return context;
};

export const ApiProvider = ({ children }) => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [threatData, setThreatData] = useState([]);

  const clearError = useCallback(() => {
    setError(null);
  }, []);

  const fetchShodanData = useCallback(async (ip) => {
    try {
      setLoading(true);
      setError(null);
      const response = await axios.get(`http://localhost:8000/api/v1/shodan/${ip}`);
      return response.data;
    } catch (err) {
      setError('Failed to fetch Shodan data');
      console.error('Shodan API error:', err);
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  const fetchVirusTotalData = useCallback(async (ip) => {
    try {
      setLoading(true);
      setError(null);
      const response = await axios.get(`/api/virustotal/${ip}`);
      return response.data;
    } catch (err) {
      setError('Failed to fetch VirusTotal data');
      console.error('VirusTotal API error:', err);
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  const fetchVirusTotalSimple = useCallback(async (ip) => {
    try {
      setLoading(true);
      setError(null);
      const response = await axios.get(`http://localhost:8000/api/v1/ip/${ip}`);
      return response.data;
    } catch (err) {
      setError('Failed to fetch VirusTotal simple data');
      console.error('VirusTotal simple API error:', err);
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  const fetchVulns=useCallback(async(keyword)=>{
    
    
   try {
    setLoading(true);
      setError(null);
       const res = await axios.get('http://localhost:8000/api/v1/cves', {
      params: { keyword } // axios handles encoding
      });
       
      
      
       
      return res.data
      } catch (error) {
      setError('Failed to fetch VirusTotal simple data');
      console.error('VirusTotal simple API error:', err);
      return null;
   }finally {
      setLoading(false);
    }


  })

  function getRandomVulnerabilities() {
  const severities = ['Low', 'Medium', 'High', 'Critical'];
  const count = Math.floor(Math.random() * 4); // 0 to 3 vulnerabilities

  const vulns = [];
  for (let i = 0; i <= count; i++) {
    const randomSeverity = severities[Math.floor(Math.random() * severities.length)];
    vulns.push(randomSeverity);
  }

  return vulns;
}

function calculateRiskLevel(vulns, openPorts = 0) {
  if (vulns.includes('Critical') || vulns.includes('High')) {
    return 'High';
  } else if (vulns.length > 0 || openPorts > 5) {
    return 'Medium';
  } else {
    return 'Low';
  }
}

// Example usage
const randomVulns = getRandomVulnerabilities();
const openPorts = Math.floor(Math.random() * 10); // Simulated port count
const riskLevel = calculateRiskLevel(randomVulns, openPorts);


  const analyzeThreat = useCallback(async (ip) => {
    try {
      setLoading(true);
      setError(null);

      const [shodanData, vtSimpleData] = await Promise.all([
        fetchShodanData(ip),
        fetchVirusTotalSimple(ip)
      ]);

      if (shodanData && vtSimpleData) {
        console.log("sh",shodanData);  
        console.log("vt",vtSimpleData);
        
        const threatInfo = {
          id: `threat-${Date.now()}`,
          ip,
          country: shodanData.data[0]?.location?.country_name || 'Unknown',
          city: shodanData.data[0]?.location?.city || 'Unknown',
          org: shodanData.org,
          ports:shodanData.ports,                  // vtSimpleData.ports,
          vulnerabilities:randomVulns,              // vtSimpleData.vulns,
          riskLevel:riskLevel,
           
          lastSeen: new Date().toISOString(),
          services: shodanData.data.map((item) => item.product || 'Unknown').filter(Boolean)
        };

        setThreatData((prev) => [threatInfo, ...prev.slice(0, 9)]);
      }
    } catch (err) {
      setError('Failed to analyze threat');
      console.error('Threat analysis error:', err);
    } finally {
      setLoading(false);
    }
  }, [fetchShodanData, fetchVirusTotalSimple]);

  const value = {
    loading,
    error,
    threatData,
    fetchShodanData,
    fetchVirusTotalData,
    fetchVirusTotalSimple,
    analyzeThreat,
    clearError,
    fetchVulns
  };

  return <ApiContext.Provider value={value}>{children}</ApiContext.Provider>;
};
