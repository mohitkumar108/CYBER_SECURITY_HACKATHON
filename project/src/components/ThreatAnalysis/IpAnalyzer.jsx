import React, { useState } from "react";
import { Search, Loader, AlertCircle } from "lucide-react";
import { useApi } from "../../context/ApiContext";

const IpAnalyzer = () => {
  const [ipAddress, setIpAddress] = useState("");
  const [keyword, setkeyword] = useState("");
  const { loading, error, analyzeThreat, clearError, fetchVulns } = useApi();
  const [vulns, setVulns] = useState();
  const [cveId, setcveID] = useState([]);
  const [vulloading,setvulloading]=useState(false)

  const handleAnalyze = async (e) => {
    e.preventDefault();
    if (!ipAddress.trim()) return;

    clearError();
    await analyzeThreat(ipAddress.trim());
  };

  const validateIp = (ip) => {
    const ipRegex =
      /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    return ipRegex.test(ip);
  };

  const isValidIp = ipAddress === "" || validateIp(ipAddress);

  const handleVuln = async (e) => {
    e.preventDefault();
    console.log(keyword);
    try {
      setvulloading(true)
      const res = await fetchVulns(keyword);
  
      setVulns(res);
      console.log(
        "xs",
        res.vulnerabilities.map((s) => {
          console.log(s.cve.id);
          setcveID((prev) => [...prev, s.cve.id]);
        })
      );
      setvulloading(false)
    } catch (error) {
      setvulloading(false)
      console.log(error);
      
      
    }
  };

  return (
    <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
      <div className="flex items-center gap-3 mb-6">
        <Search className="h-6 w-6 text-primary-600" />
        <h3 className="text-lg font-semibold text-gray-800">
          IP Address Analyzer
        </h3>
      </div>

      <form onSubmit={handleAnalyze} className="space-y-4">
        <div>
          <label
            htmlFor="ip-input"
            className="block text-sm font-medium text-gray-700 mb-2"
          >
            Enter IP Address to Analyze
          </label>
          <div className="relative">
            <input
              id="ip-input"
              type="text"
              value={ipAddress}
              onChange={(e) => setIpAddress(e.target.value)}
              placeholder="e.g., 1.1.1.1"
              className={`w-full px-4 py-3 border rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent transition-colors ${
                !isValidIp ? "border-red-300 bg-red-50" : "border-gray-300"
              }`}
              disabled={loading}
            />
            {!isValidIp && (
              <div className="absolute right-3 top-1/2 transform -translate-y-1/2">
                <AlertCircle className="h-5 w-5 text-red-500" />
              </div>
            )}
          </div>
          {!isValidIp && (
            <p className="text-sm text-red-600 mt-1">
              Please enter a valid IP address
            </p>
          )}
        </div>

        {error && (
          <div className="p-3 bg-red-50 border border-red-200 rounded-lg">
            <div className="flex items-center gap-2">
              <AlertCircle className="h-4 w-4 text-red-600" />
              <p className="text-sm text-red-700">{error}</p>
            </div>
          </div>
        )}

        <button
          type="submit"
          disabled={loading || !isValidIp || !ipAddress.trim()}
          className="w-full bg-primary-600 text-white py-3 px-4 rounded-lg hover:bg-primary-700 disabled:bg-gray-300 disabled:cursor-not-allowed transition-colors flex items-center justify-center gap-2"
        >
          {loading ? (
            <>
              <Loader className="h-4 w-4 animate-spin" />
              Analyzing...
            </>
          ) : (
            <>
              <Search className="h-4 w-4" />
              Analyze Threat
            </>
          )}
        </button>
      </form>

      <div className="mt-6 p-4 bg-blue-50 border border-blue-200 rounded-lg">
        <h4 className="font-medium text-blue-800 mb-2">Analysis includes:</h4>
        <ul className="text-sm text-blue-700 space-y-1">
          <li>• Geolocation and ISP information</li>
          <li>• Open ports and running services</li>
          <li>• Known vulnerabilities</li>
          <li>• Threat intelligence data</li>
          <li>• Historical attack patterns</li>
        </ul>
      </div>

      <div className="flex items-center gap-3 mt-8 mb-6">
        <Search className="h-6 w-6 text-primary-600" />
        <h3 className="text-lg font-semibold text-gray-800">
          Vulnerabilities Analyzer
        </h3>
      </div>

      <form onSubmit={handleVuln} className="space-y-4">
        <div>
          <label
            htmlFor="ip-input"
            className="block text-sm font-medium text-gray-700 mb-2"
          >
            Enter Vulnerability Analyze
          </label>
          <div className="relative">
            <input
              id="ip-input"
              type="text"
              value={keyword}
              onChange={(e) => setkeyword(e.target.value)}
              placeholder="e.g., TFTP 1.3"
              className={`w-full px-4 py-3 border rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent transition-colors ${
                !isValidIp ? "border-red-300 bg-red-50" : "border-gray-300"
              }`}
              disabled={loading}
            />
            {/* {!isValidIp && (
              <div className="absolute right-3 top-1/2 transform -translate-y-1/2">
                <AlertCircle className="h-5 w-5 text-red-500" />
              </div>
            )} */}
          </div>
          {/* {!isValidIp && (
            <p className="text-sm text-red-600 mt-1">Please enter a valid IP address</p>
          )} */}
        </div>

        {error && (
          <div className="p-3 bg-red-50 border border-red-200 rounded-lg">
            <div className="flex items-center gap-2">
              <AlertCircle className="h-4 w-4 text-red-600" />
              <p className="text-sm text-red-700">{error}</p>
            </div>
          </div>
        )}

        <button
          type="submit"
          disabled={loading}
          className="w-full bg-primary-600 text-white py-3 px-4 rounded-lg hover:bg-primary-700 disabled:bg-gray-300 disabled:cursor-not-allowed transition-colors flex items-center justify-center gap-2"
        >
          {vulloading ? (
            <>
              <Loader className="h-4 w-4 animate-spin" />
              Analyzing...
            </>
          ) : (
            <>
              <Search className="h-4 w-4" />
              Analyze Vulnerability
            </>
          )}
        </button>
      </form>

      {cveId.length ? (
        <div className="w-full h-auto">
          <h2 className="text-lg font-semibold mb-2 mt-3">CVE ID'S</h2>
          {cveId.map((x, i) => (
            <div key={i}>
              <span className="text-xl text-teal-800">CVE ID: {x}</span>
              <span className="ml-5">
                Documentation Link:{" "}
                <a
                  href={`https://www.cve.org/CVERecord?id=${x}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-blue-600 underline"
                >
                  Link
                </a>
              </span>
            </div>
          ))}
        </div>
      ) : null}
    </div>
  );
};

export default IpAnalyzer;
