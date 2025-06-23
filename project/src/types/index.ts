// Shodan API Types
export interface ShodanLocation {
  city: string;
  region_code: string;
  area_code: string | null;
  longitude: number;
  latitude: number;
  country_code: string;
  country_name: string;
}

export interface ShodanDNS {
  software: string | null;
  recursive: boolean;
  resolver_id: string;
  resolver_hostname: string | null;
}

export interface ShodanHTTP {
  status: number;
  title: string;
  server: string;
  waf?: string;
  host: string;
  html?: string;
}

export interface ShodanDataItem {
  asn: string;
  hash: number;
  os: string | null;
  timestamp: string;
  isp: string;
  transport: string;
  hostnames: string[];
  location: ShodanLocation;
  dns?: ShodanDNS;
  http?: ShodanHTTP;
  ip: number;
  domains: string[];
  org: string;
  data: string;
  port: number;
  ip_str: string;
  product?: string;
}

export interface ShodanResponse {
  region_code: string;
  tags: string[];
  ip: number;
  area_code: string | null;
  domains: string[];
  hostnames: string[];
  country_code: string;
  org: string;
  data: ShodanDataItem[];
}

// VirusTotal API Types
export interface VirusTotalRDAP {
  object_class_name: string;
  handle: string;
  start_address: string;
  end_address: string;
  ip_version: string;
  name: string;
  type: string;
  status: string[];
}

export interface VirusTotalAttributes {
  rdap: VirusTotalRDAP;
}

export interface VirusTotalData {
  id: string;
  type: string;
  attributes: VirusTotalAttributes;
}

export interface VirusTotalResponse {
  data: VirusTotalData;
}

export interface VirusTotalSimpleResponse {
  cpes: string[];
  hostnames: string[];
  ip: string;
  ports: number[];
  tags: string[];
  vulns: string[];
}

// Dashboard Types
export interface ThreatData {
  id: string;
  ip: string;
  country: string;
  city: string;
  org: string;
  ports: number[];
  vulnerabilities: string[];
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  lastSeen: string;
  services: string[];
}

export interface DashboardStats {
  totalThreats: number;
  activeMonitoring: number;
  vulnerabilities: number;
  blockedAttacks: number;
}