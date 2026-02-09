from nicegui import ui
from pathlib import Path
import subprocess
import sys
import json
from collections import deque

"""
This is the frontend dashboard for the app using NiceGUI.
It handles the starting and stopping of the different processes, and shows alerts and statuses currently with
tables for the logs.
"""


LOG_DIR = Path('honeypot_logs')
BASELINE_DIR = Path('baseline_logs')

detect_process = None
honeypot_process = None
detect_log_handle = None
honeypot_log_handle = None

LLM_HOST = '192.168.1.71'
LLM_PORT = '5555'
LLM_MODEL = 'qwen2.5:3b'
LLM_TIMEOUT = '60'


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
            dq = deque(f, maxlen=500)
            for line in dq:
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
            dq = deque(f, maxlen=500)
            for line in dq:

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


def load_llm_logs():
    rows = []

    p = Path('llm_alerts.log')
    if not p.exists():
        return rows
    try:
        with p.open('r') as f:
            dq = deque(f, maxlen=500)
            for line in dq:

                line = line.strip()

                if not line:
                    continue

                try:
                    obj = json.loads(line)
                    llm = obj.get('llm', {})
                    rows.append({
                        'timestamp': obj.get('timestamp', obj.get('ts', '')),
                        'type': obj.get('type', ''),
                        'label': llm.get('label', ''),
                        'confidence': llm.get('confidence', ''),
                        'summary': llm.get('summary', ''),
                        'view': '',
                    })
                except Exception:
                    rows.append({
                        'timestamp': '',
                        'type': '',
                        'label': '',
                        'confidence': '',
                        'summary': line,
                        'view': '',
                    })
    except Exception:
        pass

    rows.reverse()
    return rows




# starts IDS
def start_ids():
    global detect_process
    global detect_log_handle

    if detect_process is not None and detect_process.poll() is None:
        return
    
    try:
        detect_log_handle = Path('detect_process.log').open('a', buffering=1)
        detect_process = subprocess.Popen(
            [sys.executable, '-u', 'detect.py', '--net', '--isoforest', '--baseline', '1000', '--contamination', '0.015', '--llm', '--llm-host', LLM_HOST, '--llm-port', LLM_PORT, '--llm-model', LLM_MODEL, '--llm-timeout', LLM_TIMEOUT],
            stdout=detect_log_handle,
            stderr=subprocess.STDOUT,
        )
    except Exception:
        detect_status.set_text('error startting IDS')


# starts honeypot
def start_honeypot():
    global honeypot_process
    global honeypot_log_handle
    if honeypot_process is not None and honeypot_process.poll() is None:
        return
    
    try:
        honeypot_log_handle = Path('honeypot_process.log').open('a', buffering=1)
        honeypot_process = subprocess.Popen(
            [sys.executable, '-u', 'honeypot.py'],
            stdout=honeypot_log_handle,
            stderr=subprocess.STDOUT,
        )
    except Exception:
        honeypot_status.set_text('error starting honeypot')



# stops detection
def stop_ids():
    global detect_process
    global detect_log_handle
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
    try:
        if detect_log_handle:
            detect_log_handle.close()
    except Exception:
        pass
    detect_log_handle = None




# stops the honepot
def stop_honeypot():
    global honeypot_process
    global honeypot_log_handle
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
    try:
        if honeypot_log_handle:
            honeypot_log_handle.close()
    except Exception:
        pass
    honeypot_log_handle = None


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

llm_columns = [
    {'name': 'timestamp', 'label': 'Timestamp', 'field': 'timestamp', 'sortable': True},
    {'name': 'type', 'label': 'Type', 'field': 'type', 'sortable': True},
    {'name': 'label', 'label': 'Label', 'field': 'label', 'sortable': True},
    {'name': 'confidence', 'label': 'Confidence', 'field': 'confidence', 'sortable': True},
    {'name': 'view', 'label': 'Summary', 'field': 'view', 'sortable': False},
]




with ui.dialog() as summary_dialog:
    with ui.card():
        ui.label('Summary')
        summary_text = ui.label('')
        ui.button('Close', on_click=summary_dialog.close)



def show_summary(e):
    row = e.args
    if not isinstance(row, dict):
        return
    summary_text.set_text(str(row.get('summary', '')))
    summary_dialog.open()




with ui.column().classes('w-full'):
    ui.label('Alerts')

    alerts_table = ui.table(columns=alert_columns, rows=load_alert_logs(), pagination=10).classes('w-full')
    ui.button('Refresh alerts', on_click=lambda: alerts_table.update_rows(load_alert_logs()))


with ui.column().classes('w-full'):
    ui.label('LLM logs')

    llm_table = ui.table(columns=llm_columns, rows=load_llm_logs(), pagination=10).classes('w-full')
    llm_table.add_slot('body-cell-view', '''
    <q-td :props="props">
    <q-btn label="View" size="sm" @click="$parent.$emit('show_summary', props.row)" />
    </q-td>
    ''')
    llm_table.on('show_summary', show_summary)
    ui.button('Refresh LLM logs', on_click=lambda: llm_table.update_rows(load_llm_logs()))


with ui.column().classes('w-full'):
    with ui.expansion('Honeypot logs'):
        honeypot_table = ui.table(columns=honeypot_columns, rows=load_honeypot_logs(), pagination=10).classes('w-full')
        ui.button('Refresh honeypot logs', on_click=lambda: honeypot_table.update_rows(load_honeypot_logs()))


def refresh():
    update_status()
    alerts_table.update_rows(load_alert_logs())
    llm_table.update_rows(load_llm_logs())



ui.timer(2.0, refresh)






if __name__ in {'__main__', '__mp_main__'}:
    ui.run(port=9000, reload=False)



