import React from 'react';
import { NavLink } from 'react-router-dom';
import { 
  Shield, 
  Activity, 
  Search, 
  AlertTriangle, 
  BarChart3,
  Settings,
  Eye
} from 'lucide-react';

const Sidebar = () => {
  const navItems = [
    { to: '/', icon: BarChart3, label: 'Dashboard' },
    { to: '/monitoring', icon: Eye, label: 'Real-time Monitoring' },
    { to: '/threat-analysis', icon: Search, label: 'Threat Analysis' },
    { to: '/vulnerabilities', icon: AlertTriangle, label: 'Vulnerabilities' },
    { to: '/activity', icon: Activity, label: 'Activity Log' },
    { to: '/settings', icon: Settings, label: 'Settings' }
  ];

  return (
    <div className="bg-gray-900 text-white w-64 min-h-screen p-4">
      <div className="flex items-center gap-3 mb-8">
        <Shield className="h-8 w-8 text-primary-400" />
        <h1 className="text-xl font-bold">SecureWatch</h1>
      </div>
      
      <nav className="space-y-2">
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            className={({ isActive }) =>
              `flex items-center gap-3 px-4 py-3 rounded-lg transition-colors duration-200 ${
                isActive
                  ? 'bg-primary-600 text-white'
                  : 'text-gray-300 hover:bg-gray-800 hover:text-white'
              }`
            }
          >
            <item.icon className="h-5 w-5" />
            <span>{item.label}</span>
          </NavLink>
        ))}
      </nav>
    </div>
  );
};

export default Sidebar;
