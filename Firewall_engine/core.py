#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Haseen Firewall Core Engine
محرك جدار الحماية الأساسي

هذا الملف يحتوي على المنطق الأساسي لنظام جدار الحماية
This file contains the core logic for the firewall system
"""

import threading
import time
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
import queue
import psutil
import yaml

from .packet_analyzer import PacketAnalyzer
from .ids_module import IDSModule
from .rules import RulesEngine
from .logger import FirewallLogger

@dataclass
class FirewallStats:
    """إحصائيات جدار الحماية"""
    total_packets: int = 0
    blocked_packets: int = 0
    allowed_packets: int = 0
    threats_detected: int = 0
    active_connections: int = 0
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    uptime: float = 0.0

class FirewallCore:
    """المحرك الأساسي لجدار الحماية"""
    
    def __init__(self, config_path: str = "config.yaml"):
        """تهيئة محرك جدار الحماية"""
        self.config = self._load_config(config_path)
        self.is_running = False
        self.start_time = None
        
        # إعداد المكونات
        self.logger = FirewallLogger(self.config.get('logging', {}))
        self.packet_analyzer = PacketAnalyzer(self.config.get('analyzer', {}))
        self.ids_module = IDSModule(self.config.get('ids', {}))
        self.rules_engine = RulesEngine(self.config.get('rules', {}))
        
        # إحصائيات النظام
        self.stats = FirewallStats()
        self.stats_lock = threading.Lock()
        
        # قائمة انتظار الحزم
        self.packet_queue = queue.Queue(maxsize=10000)
        
        # خيوط المعالجة
        self.worker_threads = []
        self.monitor_thread = None
        
        self.logger.info("تم تهيئة محرك جدار الحماية بنجاح")
    
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """تحميل ملف التكوين"""
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            # إنشاء تكوين افتراضي
            default_config = {
                'general': {
                    'mode': 'monitor',  # monitor, block, allow
                    'worker_threads': 4,
                    'queue_size': 10000
                },
                'logging': {
                    'level': 'INFO',
                    'file': 'haseen.log',
                    'max_size': '10MB',
                    'backup_count': 5
                },
                'analyzer': {
                    'deep_inspection': True,
                    'timeout': 30
                },
                'ids': {
                    'enabled': True,
                    'rules_file': 'ids_rules.yaml',
                    'alert_threshold': 5
                },
                'rules': {
                    'default_action': 'allow',
                    'rules_file': 'firewall_rules.yaml'
                }
            }
            
            with open(config_path, 'w', encoding='utf-8') as f:
                yaml.dump(default_config, f, default_flow_style=False, allow_unicode=True)
            
            return default_config
    
    def start(self) -> bool:
        """بدء تشغيل جدار الحماية"""
        if self.is_running:
            self.logger.warning("جدار الحماية يعمل بالفعل")
            return False
        
        try:
            self.is_running = True
            self.start_time = time.time()
            
            # بدء خيوط المعالجة
            num_workers = self.config.get('general', {}).get('worker_threads', 4)
            for i in range(num_workers):
                worker = threading.Thread(
                    target=self._packet_worker,
                    name=f"PacketWorker-{i}",
                    daemon=True
                )
                worker.start()
                self.worker_threads.append(worker)
            
            # بدء خيط المراقبة
            self.monitor_thread = threading.Thread(
                target=self._system_monitor,
                name="SystemMonitor",
                daemon=True
            )
            self.monitor_thread.start()
            
            self.logger.info("تم بدء تشغيل جدار الحماية بنجاح")
            return True
            
        except Exception as e:
            self.logger.error(f"خطأ في بدء تشغيل جدار الحماية: {e}")
            self.is_running = False
            return False
    
    def stop(self) -> bool:
        """إيقاف جدار الحماية"""
        if not self.is_running:
            self.logger.warning("جدار الحماية متوقف بالفعل")
            return False
        
        try:
            self.is_running = False
            
            # انتظار انتهاء الخيوط
            for worker in self.worker_threads:
                if worker.is_alive():
                    worker.join(timeout=5)
            
            if self.monitor_thread and self.monitor_thread.is_alive():
                self.monitor_thread.join(timeout=5)
            
            self.logger.info("تم إيقاف جدار الحماية بنجاح")
            return True
            
        except Exception as e:
            self.logger.error(f"خطأ في إيقاف جدار الحماية: {e}")
            return False
    
    def _packet_worker(self):
        """خيط معالجة الحزم"""
        while self.is_running:
            try:
                # محاكاة استقبال حزمة (في التطبيق الحقيقي سيتم استخدام netfilterqueue)
                packet_data = self._simulate_packet()
                if packet_data:
                    self._process_packet(packet_data)
                
                time.sleep(0.1)  # تجنب استهلاك المعالج
                
            except Exception as e:
                self.logger.error(f"خطأ في معالجة الحزمة: {e}")
    
    def _simulate_packet(self) -> Optional[Dict[str, Any]]:
        """محاكاة حزمة بيانات للاختبار"""
        import random
        
        if random.random() < 0.3:  # 30% احتمال وجود حزمة
            return {
                'src_ip': f"192.168.1.{random.randint(1, 254)}",
                'dst_ip': f"10.0.0.{random.randint(1, 254)}",
                'src_port': random.randint(1024, 65535),
                'dst_port': random.choice([80, 443, 22, 21, 25, 53]),
                'protocol': random.choice(['TCP', 'UDP', 'ICMP']),
                'size': random.randint(64, 1500),
                'timestamp': time.time(),
                'payload': f"test_payload_{random.randint(1000, 9999)}"
            }
        return None
    
    def _process_packet(self, packet_data: Dict[str, Any]):
        """معالجة حزمة البيانات"""
        try:
            with self.stats_lock:
                self.stats.total_packets += 1
            
            # تحليل الحزمة
            analysis_result = self.packet_analyzer.analyze(packet_data)
            
            # فحص IDS
            ids_result = self.ids_module.check_packet(packet_data, analysis_result)
            
            # تطبيق القواعد
            rule_result = self.rules_engine.apply_rules(packet_data, analysis_result, ids_result)
            
            # تحديث الإحصائيات
            with self.stats_lock:
                if rule_result['action'] == 'block':
                    self.stats.blocked_packets += 1
                else:
                    self.stats.allowed_packets += 1
                
                if ids_result.get('threat_detected', False):
                    self.stats.threats_detected += 1
            
            # تسجيل الحدث
            self.logger.log_packet_event(packet_data, analysis_result, ids_result, rule_result)
            
        except Exception as e:
            self.logger.error(f"خطأ في معالجة الحزمة: {e}")
    
    def _system_monitor(self):
        """مراقبة النظام"""
        while self.is_running:
            try:
                # تحديث إحصائيات النظام
                with self.stats_lock:
                    self.stats.cpu_usage = psutil.cpu_percent(interval=1)
                    self.stats.memory_usage = psutil.virtual_memory().percent
                    self.stats.active_connections = len(psutil.net_connections())
                    
                    if self.start_time:
                        self.stats.uptime = time.time() - self.start_time
                
                time.sleep(5)  # تحديث كل 5 ثوان
                
            except Exception as e:
                self.logger.error(f"خطأ في مراقبة النظام: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """الحصول على إحصائيات النظام"""
        with self.stats_lock:
            return asdict(self.stats)
    
    def get_status(self) -> Dict[str, Any]:
        """الحصول على حالة النظام"""
        return {
            'is_running': self.is_running,
            'start_time': self.start_time,
            'uptime': time.time() - self.start_time if self.start_time else 0,
            'worker_threads': len([t for t in self.worker_threads if t.is_alive()]),
            'queue_size': self.packet_queue.qsize(),
            'stats': self.get_stats()
        }
    
    def reload_config(self, config_path: str = "config.yaml") -> bool:
        """إعادة تحميل التكوين"""
        try:
            new_config = self._load_config(config_path)
            self.config = new_config
            
            # إعادة تهيئة المكونات
            self.rules_engine.reload_rules()
            self.ids_module.reload_rules()
            
            self.logger.info("تم إعادة تحميل التكوين بنجاح")
            return True
            
        except Exception as e:
            self.logger.error(f"خطأ في إعادة تحميل التكوين: {e}")
            return False

if __name__ == "__main__":
    # اختبار المحرك
    firewall = FirewallCore()
    
    print("بدء تشغيل جدار الحماية...")
    if firewall.start():
        try:
            while True:
                status = firewall.get_status()
                print(f"الحالة: {'يعمل' if status['is_running'] else 'متوقف'}")
                print(f"الحزم المعالجة: {status['stats']['total_packets']}")
                print(f"الحزم المحظورة: {status['stats']['blocked_packets']}")
                print(f"التهديدات المكتشفة: {status['stats']['threats_detected']}")
                print("-" * 50)
                time.sleep(10)
                
        except KeyboardInterrupt:
            print("\nإيقاف جدار الحماية...")
            firewall.stop()
    else:
        print("فشل في بدء تشغيل جدار الحماية")
