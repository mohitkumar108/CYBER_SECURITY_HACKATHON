import React from 'react';
import { AlertTriangle, Shield, Bug, Info } from 'lucide-react';
import { useApi } from '../context/ApiContext';

const Vulnerabilities = () => {
  const { threatData } = useApi();

  const allVulnerabilities = threatData.flatMap(threat =>
    threat.vulnerabilities.map(vuln => ({
      ...threat,
      vulnerability: vuln
    }))
  );

  const vulnerabilityStats = {
    total: allVulnerabilities.length,
    critical: allVulnerabilities.filter(v => v.riskLevel === 'critical').length,
    high: allVulnerabilities.filter(v => v.riskLevel === 'high').length,
    medium: allVulnerabilities.filter(v => v.riskLevel === 'medium').length,
    low: allVulnerabilities.filter(v => v.riskLevel === 'low').length
  };

  return (
    <div className="space-y-6">
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
        <div className="flex items-center gap-3 mb-6">
          <Bug className="h-6 w-6 text-danger-600" />
          <h2 className="text-xl font-semibold text-gray-800">Vulnerability Assessment</h2>
        </div>

        {/* Vulnerability Stats */}
        <div className="grid grid-cols-1 md:grid-cols-5 gap-4 mb-8">
          <div className="p-4 bg-gray-50 border border-gray-200 rounded-lg text-center">
            <p className="text-2xl font-bold text-gray-800">{vulnerabilityStats.total}</p>
            <p className="text-sm text-gray-600">Total</p>
          </div>
          <div className="p-4 bg-red-50 border border-red-200 rounded-lg text-center">
            <p className="text-2xl font-bold text-red-800">{vulnerabilityStats.critical}</p>
            <p className="text-sm text-red-600">Critical</p>
          </div>
          <div className="p-4 bg-orange-50 border border-orange-200 rounded-lg text-center">
            <p className="text-2xl font-bold text-orange-800">{vulnerabilityStats.high}</p>
            <p className="text-sm text-orange-600">High</p>
          </div>
          <div className="p-4 bg-yellow-50 border border-yellow-200 rounded-lg text-center">
            <p className="text-2xl font-bold text-yellow-800">{vulnerabilityStats.medium}</p>
            <p className="text-sm text-yellow-600">Medium</p>
          </div>
          <div className="p-4 bg-green-50 border border-green-200 rounded-lg text-center">
            <p className="text-2xl font-bold text-green-800">{vulnerabilityStats.low}</p>
            <p className="text-sm text-green-600">Low</p>
          </div>
        </div>

        {/* Vulnerability List */}
        <div className="space-y-4">
          <h3 className="text-lg font-semibold text-gray-800">Detected Vulnerabilities</h3>

          {allVulnerabilities.length > 0 ? (
            <div className="space-y-3">
              {allVulnerabilities.map((item, index) => (
                <div key={index} className="p-4 border border-gray-200 rounded-lg">
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center gap-3">
                      <AlertTriangle className={`h-5 w-5 ${
                        item.riskLevel === 'critical' ? 'text-red-600' :
                        item.riskLevel === 'high' ? 'text-orange-600' :
                        item.riskLevel === 'medium' ? 'text-yellow-600' : 'text-green-600'
                      }`} />
                      <div>
                        <p className="font-medium text-gray-800">{item.vulnerability}</p>
                        <p className="text-sm text-gray-600">Affected IP: {item.ip}</p>
                      </div>
                    </div>
                    <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                      item.riskLevel === 'critical' ? 'bg-red-100 text-red-800' :
                      item.riskLevel === 'high' ? 'bg-orange-100 text-orange-800' :
                      item.riskLevel === 'medium' ? 'bg-yellow-100 text-yellow-800' : 'bg-green-100 text-green-800'
                    }`}>
                      {item.riskLevel.toUpperCase()}
                    </span>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
                    <div>
                      <p className="text-gray-600">Location</p>
                      <p className="font-medium">{item.city}, {item.country}</p>
                    </div>
                    <div>
                      <p className="text-gray-600">Organization</p>
                      <p className="font-medium truncate">{item.org}</p>
                    </div>
                    <div>
                      <p className="text-gray-600">Last Detected</p>
                      <p className="font-medium">{new Date(item.lastSeen).toLocaleDateString()}</p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-12 text-gray-500">
              <Shield className="h-16 w-16 mx-auto mb-4 text-gray-300" />
              <h3 className="text-lg font-medium text-gray-700 mb-2">No Vulnerabilities Detected</h3>
              <p>Your monitored systems appear to be secure</p>
              <div className="mt-4 p-4 bg-blue-50 border border-blue-200 rounded-lg inline-block">
                <div className="flex items-center gap-2 text-blue-700">
                  <Info className="h-4 w-4" />
                  <span className="text-sm">Analyze more IPs to discover potential vulnerabilities</span>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Vulnerabilities;
