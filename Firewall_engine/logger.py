#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Haseen Firewall Logger
نظام تسجيل جدار الحماية

هذا الملف يحتوي على نظام التسجيل والتقارير
This file contains logging and reporting system
"""

import logging
import json
import time
import os
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from logging.handlers import RotatingFileHandler
import sqlite3
import threading
from dataclasses import dataclass, asdict

@dataclass
class LogEntry:
    """سجل حدث"""
    timestamp: float
    event_type: str
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    action: str
    rule_id: Optional[str]
    threat_detected: bool
    threat_types: List[str]
    risk_score: int
    packet_size: int
    details: Dict[str, Any]

class FirewallLogger:
    """نظام تسجيل جدار الحماية"""
    
    def __init__(self, config: Dict[str, Any]):
        """تهيئة نظام التسجيل"""
        self.config = config
        self.log_level = config.get('level', 'INFO')
        self.log_file = config.get('file', 'haseen.log')
        self.max_size = config.get('max_size', '10MB')
        self.backup_count = config.get('backup_count', 5)
        self.db_file = config.get('db_file', 'haseen_logs.db')
        
        # إعداد نظام التسجيل النصي
        self._setup_file_logging()
        
        # إعداد قاعدة البيانات
        self._setup_database()
        
        # قفل للكتابة المتزامنة
        self.db_lock = threading.Lock()
        
        # إحصائيات التسجيل
        self.log_stats = {
            'total_events': 0,
            'blocked_events': 0,
            'allowed_events': 0,
            'threat_events': 0,
            'start_time': time.time()
        }
    
    def _setup_file_logging(self):
        """إعداد تسجيل الملفات"""
        # تحويل حجم الملف من نص إلى بايت
        size_map = {'KB': 1024, 'MB': 1024*1024, 'GB': 1024*1024*1024}
        max_bytes = 10 * 1024 * 1024  # افتراضي 10MB
        
        if isinstance(self.max_size, str):
            for unit, multiplier in size_map.items():
                if unit in self.max_size.upper():
                    size_num = float(self.max_size.upper().replace(unit, ''))
                    max_bytes = int(size_num * multiplier)
                    break
        
        # إنشاء مجلد السجلات
        log_dir = os.path.dirname(self.log_file) if os.path.dirname(self.log_file) else 'logs'
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        # إعداد المسجل
        self.logger = logging.getLogger('haseen_firewall')
        self.logger.setLevel(getattr(logging, self.log_level.upper()))
        
        # إزالة المعالجات الموجودة
        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)
        
        # معالج الملف الدوار
        file_handler = RotatingFileHandler(
            self.log_file,
            maxBytes=max_bytes,
            backupCount=self.backup_count,
            encoding='utf-8'
        )
        
        # تنسيق السجل
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(formatter)
        
        # معالج وحدة التحكم
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        
        # إضافة المعالجات
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
    
    def _setup_database(self):
        """إعداد قاعدة البيانات"""
        try:
            # إنشاء مجلد قاعدة البيانات
            db_dir = os.path.dirname(self.db_file) if os.path.dirname(self.db_file) else 'data'
            if db_dir and not os.path.exists(db_dir):
                os.makedirs(db_dir)
            
            self.conn = sqlite3.connect(self.db_file, check_same_thread=False)
            self.conn.execute('PRAGMA journal_mode=WAL')  # تحسين الأداء
            
            # إنشاء جدول السجلات
            self.conn.execute('''
                CREATE TABLE IF NOT EXISTS firewall_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    event_type TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    destination_ip TEXT NOT NULL,
                    source_port INTEGER,
                    destination_port INTEGER,
                    protocol TEXT,
                    action TEXT NOT NULL,
                    rule_id TEXT,
                    threat_detected BOOLEAN DEFAULT FALSE,
                    threat_types TEXT,
                    risk_score INTEGER DEFAULT 0,
                    packet_size INTEGER DEFAULT 0,
                    details TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # إنشاء فهارس للبحث السريع
            self.conn.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON firewall_logs(timestamp)')
            self.conn.execute('CREATE INDEX IF NOT EXISTS idx_source_ip ON firewall_logs(source_ip)')
            self.conn.execute('CREATE INDEX IF NOT EXISTS idx_action ON firewall_logs(action)')
            self.conn.execute('CREATE INDEX IF NOT EXISTS idx_threat ON firewall_logs(threat_detected)')
            
            # إنشاء جدول الإحصائيات
            self.conn.execute('''
                CREATE TABLE IF NOT EXISTS statistics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    date TEXT NOT NULL,
                    total_packets INTEGER DEFAULT 0,
                    blocked_packets INTEGER DEFAULT 0,
                    allowed_packets INTEGER DEFAULT 0,
                    threats_detected INTEGER DEFAULT 0,
                    top_sources TEXT,
                    top_destinations TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(date)
                )
            ''')
            
            self.conn.commit()
            
        except Exception as e:
            self.logger.error(f"خطأ في إعداد قاعدة البيانات: {e}")
    
    def log_packet_event(self, packet_data: Dict[str, Any], 
                        analysis_result: Any, ids_result: Dict[str, Any],
                        rule_result: Any):
        """تسجيل حدث حزمة"""
        try:
            # إنشاء سجل الحدث
            log_entry = LogEntry(
                timestamp=packet_data.get('timestamp', time.time()),
                event_type='packet_processed',
                source_ip=packet_data.get('src_ip', ''),
                destination_ip=packet_data.get('dst_ip', ''),
                source_port=packet_data.get('src_port', 0),
                destination_port=packet_data.get('dst_port', 0),
                protocol=packet_data.get('protocol', ''),
                action=rule_result.action if hasattr(rule_result, 'action') else 'unknown',
                rule_id=rule_result.rule_id if hasattr(rule_result, 'rule_id') else None,
                threat_detected=ids_result.get('threat_detected', False),
                threat_types=ids_result.get('threat_types', []),
                risk_score=ids_result.get('risk_score', 0),
                packet_size=packet_data.get('size', 0),
                details={
                    'analysis': asdict(analysis_result) if hasattr(analysis_result, '__dict__') else {},
                    'ids_alerts': len(ids_result.get('alerts', [])),
                    'rule_reason': rule_result.reason if hasattr(rule_result, 'reason') else ''
                }
            )
            
            # تسجيل في الملف
            self._log_to_file(log_entry)
            
            # تسجيل في قاعدة البيانات
            self._log_to_database(log_entry)
            
            # تحديث الإحصائيات
            self._update_stats(log_entry)
            
        except Exception as e:
            self.logger.error(f"خطأ في تسجيل الحدث: {e}")
    
    def _log_to_file(self, log_entry: LogEntry):
        """تسجيل في الملف"""
        try:
            # تحديد مستوى التسجيل
            if log_entry.threat_detected:
                level = logging.WARNING
                message = f"تهديد مكتشف - {log_entry.source_ip}:{log_entry.source_port} -> {log_entry.destination_ip}:{log_entry.destination_port} [{log_entry.protocol}] - {log_entry.action} - التهديدات: {', '.join(log_entry.threat_types)}"
            elif log_entry.action in ['block', 'drop']:
                level = logging.INFO
                message = f"حزمة محظورة - {log_entry.source_ip}:{log_entry.source_port} -> {log_entry.destination_ip}:{log_entry.destination_port} [{log_entry.protocol}] - القاعدة: {log_entry.rule_id}"
            else:
                level = logging.DEBUG
                message = f"حزمة مسموحة - {log_entry.source_ip}:{log_entry.source_port} -> {log_entry.destination_ip}:{log_entry.destination_port} [{log_entry.protocol}]"
            
            self.logger.log(level, message)
            
        except Exception as e:
            print(f"خطأ في التسجيل النصي: {e}")
    
    def _log_to_database(self, log_entry: LogEntry):
        """تسجيل في قاعدة البيانات"""
        try:
            with self.db_lock:
                self.conn.execute('''
                    INSERT INTO firewall_logs (
                        timestamp, event_type, source_ip, destination_ip,
                        source_port, destination_port, protocol, action,
                        rule_id, threat_detected, threat_types, risk_score,
                        packet_size, details
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    log_entry.timestamp,
                    log_entry.event_type,
                    log_entry.source_ip,
                    log_entry.destination_ip,
                    log_entry.source_port,
                    log_entry.destination_port,
                    log_entry.protocol,
                    log_entry.action,
                    log_entry.rule_id,
                    log_entry.threat_detected,
                    json.dumps(log_entry.threat_types, ensure_ascii=False),
                    log_entry.risk_score,
                    log_entry.packet_size,
                    json.dumps(log_entry.details, ensure_ascii=False)
                ))
                self.conn.commit()
                
        except Exception as e:
            self.logger.error(f"خطأ في التسجيل في قاعدة البيانات: {e}")
    
    def _update_stats(self, log_entry: LogEntry):
        """تحديث الإحصائيات"""
        self.log_stats['total_events'] += 1
        
        if log_entry.action in ['block', 'drop']:
            self.log_stats['blocked_events'] += 1
        elif log_entry.action == 'allow':
            self.log_stats['allowed_events'] += 1
        
        if log_entry.threat_detected:
            self.log_stats['threat_events'] += 1
    
    def get_recent_logs(self, limit: int = 100, 
                       filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """الحصول على السجلات الأخيرة"""
        try:
            query = "SELECT * FROM firewall_logs"
            params = []
            conditions = []
            
            if filters:
                if 'source_ip' in filters:
                    conditions.append("source_ip = ?")
                    params.append(filters['source_ip'])
                
                if 'action' in filters:
                    conditions.append("action = ?")
                    params.append(filters['action'])
                
                if 'threat_detected' in filters:
                    conditions.append("threat_detected = ?")
                    params.append(filters['threat_detected'])
                
                if 'start_time' in filters:
                    conditions.append("timestamp >= ?")
                    params.append(filters['start_time'])
                
                if 'end_time' in filters:
                    conditions.append("timestamp <= ?")
                    params.append(filters['end_time'])
            
            if conditions:
                query += " WHERE " + " AND ".join(conditions)
            
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            
            with self.db_lock:
                cursor = self.conn.execute(query, params)
                rows = cursor.fetchall()
                
                # تحويل النتائج إلى قواميس
                columns = [description[0] for description in cursor.description]
                results = []
                
                for row in rows:
                    log_dict = dict(zip(columns, row))
                    
                    # تحويل JSON strings إلى objects
                    if log_dict['threat_types']:
                        try:
                            log_dict['threat_types'] = json.loads(log_dict['threat_types'])
                        except:
                            log_dict['threat_types'] = []
                    
                    if log_dict['details']:
                        try:
                            log_dict['details'] = json.loads(log_dict['details'])
                        except:
                            log_dict['details'] = {}
                    
                    results.append(log_dict)
                
                return results
                
        except Exception as e:
            self.logger.error(f"خطأ في استرجاع السجلات: {e}")
            return []
    
    def get_statistics(self, days: int = 7) -> Dict[str, Any]:
        """الحصول على إحصائيات مفصلة"""
        try:
            end_time = time.time()
            start_time = end_time - (days * 24 * 3600)
            
            with self.db_lock:
                # إحصائيات عامة
                cursor = self.conn.execute('''
                    SELECT 
                        COUNT(*) as total,
                        SUM(CASE WHEN action IN ('block', 'drop') THEN 1 ELSE 0 END) as blocked,
                        SUM(CASE WHEN action = 'allow' THEN 1 ELSE 0 END) as allowed,
                        SUM(CASE WHEN threat_detected = 1 THEN 1 ELSE 0 END) as threats
                    FROM firewall_logs 
                    WHERE timestamp >= ?
                ''', (start_time,))
                
                general_stats = cursor.fetchone()
                
                # أكثر المصادر نشاطاً
                cursor = self.conn.execute('''
                    SELECT source_ip, COUNT(*) as count
                    FROM firewall_logs 
                    WHERE timestamp >= ?
                    GROUP BY source_ip
                    ORDER BY count DESC
                    LIMIT 10
                ''', (start_time,))
                
                top_sources = [{'ip': row[0], 'count': row[1]} for row in cursor.fetchall()]
                
                # أكثر الوجهات نشاطاً
                cursor = self.conn.execute('''
                    SELECT destination_ip, COUNT(*) as count
                    FROM firewall_logs 
                    WHERE timestamp >= ?
                    GROUP BY destination_ip
                    ORDER BY count DESC
                    LIMIT 10
                ''', (start_time,))
                
                top_destinations = [{'ip': row[0], 'count': row[1]} for row in cursor.fetchall()]
                
                # إحصائيات البروتوكولات
                cursor = self.conn.execute('''
                    SELECT protocol, COUNT(*) as count
                    FROM firewall_logs 
                    WHERE timestamp >= ?
                    GROUP BY protocol
                    ORDER BY count DESC
                ''', (start_time,))
                
                protocol_stats = [{'protocol': row[0], 'count': row[1]} for row in cursor.fetchall()]
                
                # إحصائيات يومية
                cursor = self.conn.execute('''
                    SELECT 
                        DATE(datetime(timestamp, 'unixepoch')) as date,
                        COUNT(*) as total,
                        SUM(CASE WHEN action IN ('block', 'drop') THEN 1 ELSE 0 END) as blocked,
                        SUM(CASE WHEN threat_detected = 1 THEN 1 ELSE 0 END) as threats
                    FROM firewall_logs 
                    WHERE timestamp >= ?
                    GROUP BY date
                    ORDER BY date DESC
                ''', (start_time,))
                
                daily_stats = []
                for row in cursor.fetchall():
                    daily_stats.append({
                        'date': row[0],
                        'total': row[1],
                        'blocked': row[2],
                        'threats': row[3]
                    })
                
                return {
                    'period_days': days,
                    'general': {
                        'total_events': general_stats[0] if general_stats else 0,
                        'blocked_events': general_stats[1] if general_stats else 0,
                        'allowed_events': general_stats[2] if general_stats else 0,
                        'threat_events': general_stats[3] if general_stats else 0
                    },
                    'top_sources': top_sources,
                    'top_destinations': top_destinations,
                    'protocol_distribution': protocol_stats,
                    'daily_activity': daily_stats,
                    'current_stats': self.log_stats
                }
                
        except Exception as e:
            self.logger.error(f"خطأ في حساب الإحصائيات: {e}")
            return {}
    
    def export_logs(self, output_file: str, format: str = 'json',
                   filters: Optional[Dict[str, Any]] = None) -> bool:
        """تصدير السجلات"""
        try:
            logs = self.get_recent_logs(limit=10000, filters=filters)
            
            if format.lower() == 'json':
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(logs, f, ensure_ascii=False, indent=2, default=str)
            
            elif format.lower() == 'csv':
                import csv
                if logs:
                    with open(output_file, 'w', newline='', encoding='utf-8') as f:
                        writer = csv.DictWriter(f, fieldnames=logs[0].keys())
                        writer.writeheader()
                        writer.writerows(logs)
            
            return True
            
        except Exception as e:
            self.logger.error(f"خطأ في تصدير السجلات: {e}")
            return False
    
    def cleanup_old_logs(self, days: int = 30) -> bool:
        """تنظيف السجلات القديمة"""
        try:
            cutoff_time = time.time() - (days * 24 * 3600)
            
            with self.db_lock:
                cursor = self.conn.execute(
                    "DELETE FROM firewall_logs WHERE timestamp < ?",
                    (cutoff_time,)
                )
                deleted_count = cursor.rowcount
                self.conn.commit()
            
            self.logger.info(f"تم حذف {deleted_count} سجل قديم")
            return True
            
        except Exception as e:
            self.logger.error(f"خطأ في تنظيف السجلات: {e}")
            return False
    
    def info(self, message: str):
        """تسجيل رسالة معلومات"""
        self.logger.info(message)
    
    def warning(self, message: str):
        """تسجيل رسالة تحذير"""
        self.logger.warning(message)
    
    def error(self, message: str):
        """تسجيل رسالة خطأ"""
        self.logger.error(message)
    
    def debug(self, message: str):
        """تسجيل رسالة تصحيح"""
        self.logger.debug(message)
    
    def close(self):
        """إغلاق نظام التسجيل"""
        try:
            if hasattr(self, 'conn'):
                self.conn.close()
        except Exception as e:
            print(f"خطأ في إغلاق قاعدة البيانات: {e}")

if __name__ == "__main__":
    # اختبار نظام التسجيل
    config = {
        'level': 'INFO',
        'file': 'logs/haseen.log',
        'max_size': '10MB',
        'backup_count': 5,
        'db_file': 'data/haseen_logs.db'
    }
    
    logger = FirewallLogger(config)
    
    # اختبار التسجيل
    logger.info("بدء تشغيل نظام التسجيل")
    
    # محاكاة بيانات حزمة
    packet_data = {
        'src_ip': '192.168.1.100',
        'dst_ip': '8.8.8.8',
        'src_port': 12345,
        'dst_port': 80,
        'protocol': 'TCP',
        'size': 1024,
        'timestamp': time.time()
    }
    
    # محاكاة نتائج التحليل
    class MockAnalysis:
        def __init__(self):
            self.packet_type = 'http'
            self.risk_score = 25
    
    class MockRule:
        def __init__(self):
            self.action = 'allow'
            self.rule_id = 'ALLOW_HTTP'
            self.reason = 'حركة HTTP مسموحة'
    
    analysis = MockAnalysis()
    rule_result = MockRule()
    ids_result = {'threat_detected': False, 'alerts': [], 'threat_types': [], 'risk_score': 0}
    
    # تسجيل الحدث
    logger.log_packet_event(packet_data, analysis, ids_result, rule_result)
    
    # الحصول على الإحصائيات
    stats = logger.get_statistics(days=1)
    print(f"إجمالي الأحداث: {stats.get('general', {}).get('total_events', 0)}")
    
    # إغلاق النظام
    logger.close()
