#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Haseen CLI Tool
أداة سطر الأوامر لحصين

هذا الملف يحتوي على واجهة سطر الأوامر (CLI) لإدارة نظام جدار الحماية حصين
This file contains the Command Line Interface (CLI) for managing the Haseen firewall system
"""

import click
import os
import sys
import json
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

# إضافة مسار المشروع
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from firewall_engine.core import FirewallCore
from firewall_engine.logger import FirewallLogger

console = Console()
firewall_core = None

def get_firewall_core():
    """الحصول على مثيل FirewallCore"""
    global firewall_core
    if firewall_core is None:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True
        ) as progress:
            progress.add_task(description="تهيئة جدار الحماية...", total=None)
            firewall_core = FirewallCore()
    return firewall_core

@click.group()
def cli():
    """أداة سطر الأوامر لإدارة جدار الحماية حصين"""
    pass

@cli.command()
@click.option(
    "--mode",
    default="monitor",
    type=click.Choice(["monitor", "block", "allow"]),
    help="وضع التشغيل: monitor (مراقبة فقط), block (حظر), allow (سماح)"
)
def start(mode):
    """بدء تشغيل جدار الحماية"""
    core = get_firewall_core()
    core.config["general"]["mode"] = mode
    if core.start():
        console.print(f"[bold green]تم بدء تشغيل جدار الحماية في وضع {mode} بنجاح.[/bold green]")
        console.print("اضغط Ctrl+C للإيقاف.")
        try:
            while core.is_running:
                stats = core.get_stats()
                console.print(f"[blue]الحزم المعالجة: {stats["total_packets"]}[/blue] | "
                              f"[red]المحظورة: {stats["blocked_packets"]}[/red] | "
                              f"[green]المسموحة: {stats["allowed_packets"]}[/green] | "
                              f"[yellow]التهديدات: {stats["threats_detected"]}[/yellow] | "
                              f"[cyan]المعالج: {stats["cpu_usage"]:.1f}%[/cyan] | "
                              f"[magenta]الذاكرة: {stats["memory_usage"]:.1f}%[/magenta]",
                              highlight=False)
                time.sleep(5)
        except KeyboardInterrupt:
            console.print("\n[bold yellow]جاري إيقاف جدار الحماية...[/bold yellow]")
            core.stop()
            console.print("[bold green]تم إيقاف جدار الحماية.[/bold green]")
    else:
        console.print("[bold red]فشل في بدء تشغيل جدار الحماية.[/bold red]")

@cli.command()
def stop():
    """إيقاف جدار الحماية"""
    core = get_firewall_core()
    if core.stop():
        console.print("[bold green]تم إيقاف جدار الحماية بنجاح.[/bold green]")
    else:
        console.print("[bold red]فشل في إيقاف جدار الحماية أو أنه متوقف بالفعل.[/bold red]")

@cli.command()
def status():
    """عرض حالة جدار الحماية"""
    core = get_firewall_core()
    status_data = core.get_status()
    
    table = Table(title="حالة جدار الحماية حصين")
    table.add_column("المعلمة", style="cyan", no_wrap=True)
    table.add_column("القيمة", style="magenta")
    
    table.add_row("حالة التشغيل", "يعمل" if status_data["is_running"] else "متوقف")
    table.add_row("وقت التشغيل", f"{status_data["uptime"]:.2f} ثانية")
    table.add_row("خيوط المعالجة النشطة", str(status_data["worker_threads"]))
    table.add_row("حجم قائمة انتظار الحزم", str(status_data["queue_size"]))
    
    console.print(table)
    
    stats = status_data["stats"]
    stats_table = Table(title="إحصائيات الأداء")
    stats_table.add_column("المعلمة", style="cyan", no_wrap=True)
    stats_table.add_column("القيمة", style="magenta")
    
    stats_table.add_row("إجمالي الحزم", str(stats["total_packets"]))
    stats_table.add_row("الحزم المحظورة", str(stats["blocked_packets"]))
    stats_table.add_row("الحزم المسموحة", str(stats["allowed_packets"]))
    stats_table.add_row("التهديدات المكتشفة", str(stats["threats_detected"]))
    stats_table.add_row("استخدام المعالج", f"{stats["cpu_usage"]:.1f}%")
    stats_table.add_row("استخدام الذاكرة", f"{stats["memory_usage"]:.1f}%")
    stats_table.add_row("الاتصالات النشطة", str(stats["active_connections"]))
    
    console.print(stats_table)

@cli.command()
@click.option("--limit", default=10, help="عدد السجلات المراد عرضها")
@click.option("--source-ip", help="تصفية حسب عنوان IP المصدر")
@click.option("--action", type=click.Choice(["allow", "block", "drop"]), help="تصفية حسب الإجراء")
@click.option("--threat-detected/--no-threat-detected", default=None, help="تصفية حسب اكتشاف التهديد")
def show_logs(limit, source_ip, action, threat_detected):
    """عرض السجلات الأخيرة"""
    core = get_firewall_core()
    logger_instance = core.logger # الوصول إلى مثيل المسجل من core
    
    filters = {}
    if source_ip: filters["source_ip"] = source_ip
    if action: filters["action"] = action
    if threat_detected is not None: filters["threat_detected"] = threat_detected
    
    logs = logger_instance.get_recent_logs(limit=limit, filters=filters)
    
    if not logs:
        console.print("[bold yellow]لا توجد سجلات لعرضها.[/bold yellow]")
        return
    
    table = Table(title="السجلات الأخيرة")
    table.add_column("الوقت", style="cyan")
    table.add_column("المصدر", style="green")
    table.add_column("الوجهة", style="magenta")
    table.add_column("البروتوكول", style="blue")
    table.add_column("الإجراء", style="yellow")
    table.add_column("تهديد؟", style="red")
    table.add_column("التهديدات", style="orange")
    table.add_column("درجة المخاطر", style="purple")
    
    for log in logs:
        threat_status = "نعم" if log["threat_detected"] else "لا"
        threat_types = ", ".join(log["threat_types"]) if log["threat_types"] else "لا يوجد"
        
        table.add_row(
            datetime.fromtimestamp(log["timestamp"]).strftime("%Y-%m-%d %H:%M:%S"),
            f"{log["source_ip"]}:{log["source_port"]}",
            f"{log["destination_ip"]}:{log["destination_port"]}",
            log["protocol"],
            log["action"],
            threat_status,
            threat_types,
            str(log["risk_score"])
        )
    
    console.print(table)

@cli.command()
@click.option("--rule-id", required=True, help="معرف القاعدة")
@click.option("--name", help="اسم القاعدة")
@click.option("--action", type=click.Choice(["allow", "block", "drop"]), help="إجراء القاعدة")
@click.option("--source-ip", help="عنوان IP المصدر")
@click.option("--destination-ip", help="عنوان IP الوجهة")
@click.option("--protocol", help="البروتوكول (TCP, UDP, ICMP)")
@click.option("--destination-port", type=int, help="منفذ الوجهة")
@click.option("--enabled/--disabled", default=True, help="تفعيل/تعطيل القاعدة")
@click.option("--priority", type=int, help="أولوية القاعدة (رقم أقل يعني أولوية أعلى)")
@click.option("--description", help="وصف القاعدة")
def add_rule(rule_id, name, action, source_ip, destination_ip, protocol, destination_port, enabled, priority, description):
    """إضافة قاعدة جدار حماية جديدة"""
    core = get_firewall_core()
    rules_engine = core.rules_engine
    
    rule_data = {
        "id": rule_id,
        "name": name if name else rule_id,
        "action": action if action else "block",
        "enabled": enabled,
        "priority": priority if priority else 100,
        "description": description if description else "قاعدة مضافة عبر CLI"
    }
    if source_ip: rule_data["source_ip"] = source_ip
    if destination_ip: rule_data["destination_ip"] = destination_ip
    if protocol: rule_data["protocol"] = protocol
    if destination_port: rule_data["destination_port"] = destination_port
    
    if rules_engine.add_rule(rule_data):
        rules_engine.save_rules()
        console.print(f"[bold green]تم إضافة القاعدة {rule_id} بنجاح.[/bold green]")
    else:
        console.print(f"[bold red]فشل في إضافة القاعدة {rule_id}.[/bold red]")

@cli.command()
@click.option("--rule-id", required=True, help="معرف القاعدة المراد إزالتها")
def remove_rule(rule_id):
    """إزالة قاعدة جدار حماية"""
    core = get_firewall_core()
    rules_engine = core.rules_engine
    
    if rules_engine.remove_rule(rule_id):
        rules_engine.save_rules()
        console.print(f"[bold green]تم إزالة القاعدة {rule_id} بنجاح.[/bold green]")
    else:
        console.print(f"[bold red]فشل في إزالة القاعدة {rule_id} أو أنها غير موجودة.[/bold red]")

@cli.command()
def show_rules():
    """عرض جميع قواعد جدار الحماية"""
    core = get_firewall_core()
    rules_engine = core.rules_engine
    
    rules = rules_engine.get_rules()
    
    if not rules:
        console.print("[bold yellow]لا توجد قواعد جدار حماية معرفة.[/bold yellow]")
        return
    
    table = Table(title="قواعد جدار الحماية حصين")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("الاسم", style="green")
    table.add_column("الحالة", style="magenta")
    table.add_column("الأولوية", style="blue")
    table.add_column("الإجراء", style="yellow")
    table.add_column("المصدر", style="orange")
    table.add_column("الوجهة", style="purple")
    table.add_column("البروتوكول", style="red")
    table.add_column("المنفذ", style="green")
    table.add_column("الوصف", style="white")
    
    for rule in rules:
        table.add_row(
            rule["id"],
            rule["name"],
            "مفعل" if rule["enabled"] else "معطل",
            str(rule["priority"]),
            rule["action"],
            rule["source_ip"] if rule["source_ip"] else "أي",
            rule["destination_ip"] if rule["destination_ip"] else "أي",
            rule["protocol"] if rule["protocol"] else "أي",
            str(rule["destination_port"]) if rule["destination_port"] else "أي",
            rule["description"]
        )
    
    console.print(table)

@cli.command()
def reload_config():
    """إعادة تحميل ملف التكوين والقواعد"""
    core = get_firewall_core()
    if core.reload_config():
        console.print("[bold green]تم إعادة تحميل التكوين والقواعد بنجاح.[/bold green]")
    else:
        console.print("[bold red]فشل في إعادة تحميل التكوين والقواعد.[/bold red]")

@cli.command()
@click.option("--days", default=7, type=int, help="عدد الأيام لعرض الإحصائيات")
def show_stats(days):
    """عرض إحصائيات النظام والسجلات"""
    core = get_firewall_core()
    logger_instance = core.logger
    
    stats = logger_instance.get_statistics(days=days)
    
    if not stats:
        console.print("[bold yellow]لا توجد إحصائيات لعرضها.[/bold yellow]")
        return
    
    console.print("[bold blue]إحصائيات جدار الحماية حصين[/bold blue]")
    console.print(f"[green]الفترة الزمنية: آخر {stats["period_days"]} يوم[/green]")
    
    general_table = Table(title="إحصائيات عامة")
    general_table.add_column("المعلمة", style="cyan")
    general_table.add_column("القيمة", style="magenta")
    
    general_table.add_row("إجمالي الأحداث", str(stats["general"]["total_events"]))
    general_table.add_row("الأحداث المحظورة", str(stats["general"]["blocked_events"]))
    general_table.add_row("الأحداث المسموحة", str(stats["general"]["allowed_events"]))
    general_table.add_row("التهديدات المكتشفة", str(stats["general"]["threat_events"]))
    
    console.print(general_table)
    
    if stats["top_sources"]:
        sources_table = Table(title="أكثر 10 مصادر نشاطاً")
        sources_table.add_column("IP المصدر", style="cyan")
        sources_table.add_column("العدد", style="magenta")
        for src in stats["top_sources"]:
            sources_table.add_row(src["ip"], str(src["count"]))
        console.print(sources_table)
        
    if stats["protocol_distribution"]:
        protocol_table = Table(title="توزيع البروتوكولات")
        protocol_table.add_column("البروتوكول", style="cyan")
        protocol_table.add_column("العدد", style="magenta")
        for proto in stats["protocol_distribution"]:
            protocol_table.add_row(proto["protocol"], str(proto["count"]))
        console.print(protocol_table)
        
    if stats["daily_activity"]:
        daily_table = Table(title="النشاط اليومي")
        daily_table.add_column("التاريخ", style="cyan")
        daily_table.add_column("الإجمالي", style="magenta")
        daily_table.add_column("المحظور", style="red")
        daily_table.add_column("التهديدات", style="yellow")
        for day in stats["daily_activity"]:
            daily_table.add_row(day["date"], str(day["total"]), str(day["blocked"]), str(day["threats"]))
        console.print(daily_table)

if __name__ == "__main__":
    cli()
