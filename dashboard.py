from nicegui import ui
from pathlib import Path
import subprocess
import sys
import json

"""
This is the frontend dashboard for the app using NiceGUI.
It handles the starting and stopping of the different processes, and shows alerts and statuses currently with
tables for the logs.
"""


LOG_DIR = Path('honeypot_logs')
BASELINE_DIR = Path('baseline_logs')

detect_process = None
honeypot_process = None


# Loads the honeypot logs
def load_honeypot_logs():
    rows = []

    if not LOG_DIR.exists():
        return rows
    
    files = sorted(LOG_DIR.glob('honeypot_*.json'))

    if not files:
        return rows
    latest = files[-1]

    try:
        with latest.open('r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue

                rows.append({
                    'timestamp': obj.get('timestamp', ''),
                    'remote_ip': obj.get('remote_ip', ''),
                    'port': obj.get('port', ''),
                    'data': obj.get('data', ''),
                })
    
    except Exception:
        pass
    return rows



# def load_baseline_logs():
#     rows = []
#     if not BASELINE_DIR.exists():
#         return rows
#     files = sorted(BASELINE_DIR.glob('*.log'))
#     for p in files:
#         try:
#             with p.open('r') as f:
#                 for line in f:
#                     line = line.rstrip('\n')
#                     rows.append({
#                         'file': p.name,
#                         'line': line,
#                     })
#         except Exception:
#             continue
#     return rows





# loads alerts
def load_alert_logs():
    rows = []

    p = Path('alerts.log')
    if not p.exists():
        return rows
    try:
        with p.open('r') as f:
            for line in f:

                line = line.strip()

                if not line:
                    continue

                try:
                    obj = json.loads(line)
                except Exception:
                    continue

                rows.append({
                    'timestamp': obj.get('timestamp', ''),
                    'type': obj.get('type', ''),
                    'message': obj.get('message', ''),
                })
    except Exception:
        pass

    rows.reverse()
    return rows




# starts IDS
def start_ids():
    global detect_process

    if detect_process is not None and detect_process.poll() is None:
        return
    
    try:
        detect_process = subprocess.Popen(
            [sys.executable, '-u', 'detect.py', '--isoforest', '--baseline', '1000', '--contamination', '0.015'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        detect_status.set_text('error startting IDS')


# starts honeypot
def start_honeypot():
    global honeypot_process
    if honeypot_process is not None and honeypot_process.poll() is None:
        return
    
    try:
        honeypot_process = subprocess.Popen(
            [sys.executable, '-u', 'honeypot.py'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        honeypot_status.set_text('error starting honeypot')



# stops detection
def stop_ids():
    global detect_process
    if detect_process is None:
        return
    try:
        if detect_process.poll() is None:
            detect_process.terminate()
            try:
                detect_process.wait(timeout=5)
            except Exception:
                pass
    except Exception:
        pass
    detect_process = None




# stops the honepot
def stop_honeypot():
    global honeypot_process
    if honeypot_process is None:
        return
    
    try:
        if honeypot_process.poll() is None:
            honeypot_process.terminate()
            try:
                honeypot_process.wait(timeout=5)
            except Exception:
                pass

    except Exception:
        pass

    honeypot_process = None


# updates status of the different processes
def update_status():
    if detect_process is not None and detect_process.poll() is None:
        detect_status.set_text('running')
    else:
        detect_status.set_text('stopped')

    if honeypot_process is not None and honeypot_process.poll() is None:
        honeypot_status.set_text('running')
    else:
        honeypot_status.set_text('stopped')

    if Path('honeypot_enabled').exists():
        flag_status.set_text('honeypot activated')
    else:
        flag_status.set_text('honeypot disabled')

with ui.row().classes('w-full justify-around'):
    with ui.column():
        ui.label('Detect')
        ui.button('Start IDS', on_click=start_ids)
        ui.button('Stop IDS', on_click=stop_ids)
        detect_status = ui.label('stopped')
    with ui.column():
        ui.label('Honeypot')
        ui.button('Start honeypot', on_click=start_honeypot)
        ui.button('Stop honeypot', on_click=stop_honeypot)
        honeypot_status = ui.label('stopped')
    with ui.column():
        ui.label('Status')
        flag_status = ui.label('honeypot disabled')



honeypot_columns = [
    {'name': 'timestamp', 'label': 'Timestamp', 'field': 'timestamp', 'sortable': True},
    {'name': 'remote_ip', 'label': 'Remote IP', 'field': 'remote_ip', 'sortable': True},
    {'name': 'port', 'label': 'Port', 'field': 'port', 'sortable': True},
    {'name': 'data', 'label': 'Data', 'field': 'data', 'sortable': False}]



# baseline_columns = [
#     {'name': 'file', 'label': 'File', 'field': 'file', 'sortable': True},
#     {'name': 'line', 'label': 'Line', 'field': 'line', 'sortable': False},
# ]

alert_columns = [
    {'name': 'timestamp', 'label': 'Timestamp', 'field': 'timestamp', 'sortable': True},
    {'name': 'type', 'label': 'Type', 'field': 'type', 'sortable': True},
    {'name': 'message', 'label': 'Message', 'field': 'message', 'sortable': False},
]



with ui.column().classes('w-full'):
    ui.label('Alerts')

    alerts_table = ui.table(columns=alert_columns, rows=load_alert_logs(), pagination=10).classes('w-full')
    ui.button('Refresh alerts', on_click=lambda: alerts_table.update_rows(load_alert_logs()))


with ui.column().classes('w-full'):
    with ui.expansion('Honeypot logs'):
        honeypot_table = ui.table(columns=honeypot_columns, rows=load_honeypot_logs(), pagination=10).classes('w-full')
        ui.button('Refresh honeypot logs', on_click=lambda: honeypot_table.update_rows(load_honeypot_logs()))


def refresh():
    update_status()
    alerts_table.update_rows(load_alert_logs())



ui.timer(2.0, refresh)






if __name__ in {'__main__', '__mp_main__'}:
    ui.run(port=9000, reload=False)



