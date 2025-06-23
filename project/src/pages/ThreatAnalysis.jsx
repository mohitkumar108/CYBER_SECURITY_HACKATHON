import React from 'react';
import IpAnalyzer from '../components/ThreatAnalysis/IpAnalyzer';
import ThreatDetails from '../components/ThreatAnalysis/ThreatDetails';

const ThreatAnalysis = () => {
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <IpAnalyzer />
        <ThreatDetails />
      </div>
    </div>
  );
};

export default ThreatAnalysis;
