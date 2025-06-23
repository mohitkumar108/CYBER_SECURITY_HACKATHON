import React from 'react';
import { DivideIcon as LucideIcon } from 'lucide-react';

const StatsCard = ({ title, value, icon: Icon, trend, color }) => {
  const colorClasses = {
    primary: 'bg-primary-50 text-primary-600 border-primary-200',
    danger: 'bg-danger-50 text-danger-600 border-danger-200',
    warning: 'bg-warning-50 text-warning-600 border-warning-200',
    success: 'bg-success-50 text-success-600 border-success-200',
  };

  const iconColorClasses = {
    primary: 'text-primary-600',
    danger: 'text-danger-600',
    warning: 'text-warning-600',
    success: 'text-success-600',
  };

  return (
    <div className={`p-6 rounded-xl border-2 ${colorClasses[color]} transition-all duration-200 hover:shadow-lg`}>
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm font-medium text-gray-600 mb-1">{title}</p>
          <p className="text-3xl font-bold text-gray-900">{value}</p>
          {trend && (
            <p className={`text-sm mt-2 ${trend.isPositive ? 'text-success-600' : 'text-danger-600'}`}>
              {trend.isPositive ? '↗' : '↘'} {Math.abs(trend.value)}% from last week
            </p>
          )}
        </div>
        <div className={`p-3 rounded-lg ${colorClasses[color]}`}>
          <Icon className={`h-8 w-8 ${iconColorClasses[color]}`} />
        </div>
      </div>
    </div>
  );
};

export default StatsCard;
