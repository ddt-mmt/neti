import os
import threading
import uuid
import sys # For print(file=sys.stderr)

from flask import render_template, request, jsonify, Blueprint

# Import functions and global stores from logic.py
from neti_beta_02.app.logic import (
    scan_results_store, cancellation_flags, config_cancellation_flags, active_processes,
    perform_scan_and_analyze, perform_config_analysis, perform_log_analysis_async, chat_with_gemini
)

bp = Blueprint('main', __name__)

@bp.route('/')
def index():
    return render_template('index.html')

@bp.route('/log_analyzer')
def log_analyzer_page():
    return render_template('log_analyzer.html')

@bp.route('/config_analyzer')
def config_analyzer_page():
    return render_template('config_analyzer.html')

@bp.route('/network_device_analyzer')
def network_device_analyzer_page():
    return render_template('network_device_analyzer.html')

@bp.route('/run_config_analysis', methods=['POST'])
def run_config_analysis():
    """Connects to a device via SSH, gets config, and analyzes it asynchronously."""
    try:
        data = request.json
        device_type = data.get('device_type')
        host = data.get('host')
        username = data.get('username')
        password = data.get('password')
        api_key = os.getenv('API_KEY') # Get API key from environment

        config_id = str(uuid.uuid4())
        threading.Thread(target=perform_config_analysis, args=(config_id, device_type, host, username, password, api_key)).start()
        return jsonify({'config_id': config_id, 'status': 'started'})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/scan', methods=['POST'])
def scan():
    try:
        data = request.json
        print(f"--- /scan request data: {data} ---", file=sys.stderr)
        print(f"--- /scan request headers: {request.headers} ---", file=sys.stderr)
        target = data.get('host')
        ports = data.get('ports')
        ai_api_key = data.get('apiKey') # Get API key from request body
        print(f"--- /scan received API Key (masked): {ai_api_key[:5]}...{ai_api_key[-5:] if ai_api_key else '[EMPTY/NONE]'} ---", file=sys.stderr)
        scan_type = data.get('scan_type', 'nmap')
        lang = data.get('lang', 'en')

        if not target:
            return jsonify({'error': 'Host cannot be empty'}), 400

        scan_id = str(uuid.uuid4())
        print("--- PRE-THREAD --- (User Input)", file=sys.stderr)
        threading.Thread(target=perform_scan_and_analyze, args=(scan_id, target, ports, ai_api_key, scan_type, lang)).start()
        print("--- POST-THREAD --- (User Input)", file=sys.stderr)
        return jsonify({'scan_id': scan_id, 'status': 'started'})

    except Exception as e:
        print(f"--- EXCEPTION IN /scan ROUTE (User Input): {e} ---", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        return jsonify({'error': str(e)}), 500

@bp.route('/cancel_scan/<scan_id>', methods=['POST'])
def cancel_scan(scan_id):
    global cancellation_flags, active_processes, scan_results_store
    if scan_id in cancellation_flags:
        cancellation_flags[scan_id].set()  # Signal the thread to cancel
        if scan_id in active_processes and active_processes[scan_id].poll() is None:
            # Terminate the process group to ensure all child processes are killed
            try:
                import os
                os.killpg(os.getpgid(active_processes[scan_id].pid), 9) # SIGKILL
                scan_results_store[scan_id].update({'status': 'cancelled', 'error': 'Scan cancelled by user.', 'progress': 'Scan cancelled.'})
                del active_processes[scan_id]
            except Exception as e:
                print(f"Error terminating process for scan_id {scan_id}: {e}", file=sys.stderr)
        return jsonify({'status': 'cancellation_requested', 'scan_id': scan_id})
    return jsonify({'status': 'scan_not_found', 'scan_id': scan_id}), 404

@bp.route('/cancel_config_analysis/<config_id>', methods=['POST'])
def cancel_config_analysis(config_id):
    global config_cancellation_flags, scan_results_store
    if config_id in config_cancellation_flags:
        config_cancellation_flags[config_id].set()  # Signal the thread to cancel
        scan_results_store[config_id].update({'status': 'cancelled', 'error': 'Config analysis cancelled by user.', 'progress': 'Config analysis cancelled.'})
        return jsonify({'status': 'cancellation_requested', 'config_id': config_id})
    return jsonify({'status': 'config_not_found', 'config_id': config_id}), 404

@bp.route('/scan_status/<scan_id>')
def scan_status(scan_id):
    global scan_results_store
    result = scan_results_store.get(scan_id, {'status': 'pending', 'progress': 'Waiting for scan to start...'}) 
    print(f"\n--- Scan Status for {scan_id}: {result} ---", file=sys.stderr)
    return jsonify(result)

@bp.route('/analyze_log', methods=['POST'])
def analyze_log():
    try:
        data = request.json
        log_data = data.get('log_data')
        api_key = os.getenv('API_KEY')
        lang = data.get('lang', 'en')

        if not log_data:
            return jsonify({'error': 'Log data cannot be empty.'}), 400
        if not api_key:
            return jsonify({'error': 'AI Engine API key is missing.'}), 400

        log_id = str(uuid.uuid4())
        # Store initial status
        scan_results_store[log_id] = {'status': 'running', 'progress': 'Starting log analysis...'}
        
        # Asynchronously perform analysis
        threading.Thread(target=perform_log_analysis_async, args=(log_id, log_data, api_key, lang)).start()

        return jsonify({'log_id': log_id, 'status': 'started'})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/cancel_log_analysis/<log_id>', methods=['POST'])
def cancel_log_analysis(log_id):
    global cancellation_flags, scan_results_store
    if log_id in cancellation_flags:
        cancellation_flags[log_id].set()  # Signal the thread to cancel
        scan_results_store[log_id].update({'status': 'cancelled', 'error': 'Log analysis cancelled by user.', 'progress': 'Log analysis cancelled.'})
        return jsonify({'status': 'cancellation_requested', 'log_id': log_id})
    return jsonify({'status': 'log_not_found', 'log_id': log_id}), 404

@bp.route('/log_analysis_status/<log_id>')
def log_analysis_status(log_id):
    global scan_results_store
    result = scan_results_store.get(log_id, {'status': 'pending', 'progress': 'Waiting for log analysis to start...'}) 
    print(f"\n--- Log Analysis Status for {log_id}: {result} ---", file=sys.stderr)
    return jsonify(result)

@bp.route('/config_analysis_status/<config_id>')
def config_analysis_status(config_id):
    global scan_results_store
    result = scan_results_store.get(config_id, {'status': 'pending', 'progress': 'Waiting for config analysis to start...'}) 
    print(f"\n--- Config Analysis Status for {config_id}: {result} ---", file=sys.stderr)
    return jsonify(result)

@bp.route('/chat', methods=['POST'])
def chat():
    try:
        data = request.json
        history = data.get('history')
        api_key = data.get('apiKey')
        lang = data.get('lang', 'en')

        if not history:
            return jsonify({'error': 'Conversation history cannot be empty'}), 400
        if not api_key:
            return jsonify({'error': 'AI Engine API key is missing'}), 400

        response = chat_with_gemini(api_key, history, lang)

        return jsonify({'response': response})

    except Exception as e:
        return jsonify({'error': str(e)}), 500
