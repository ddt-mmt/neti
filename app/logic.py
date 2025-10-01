import os
import nmap
import json
import google.generativeai as genai
import subprocess
import shlex
import re
import threading
import uuid
import sys
import xml.etree.ElementTree as ET
from datetime import datetime

import paramiko

# Global store for scan results
scan_results_store = {}
# Global store for cancellation events
cancellation_flags = {}
# Global store for config analysis cancellation events
config_cancellation_flags = {}

active_processes = {}

def run_command(command, scan_id=None):
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if scan_id:
            active_processes[scan_id] = process
        stdout, stderr = process.communicate()
        if scan_id and scan_id in active_processes:
            del active_processes[scan_id]
        if process.returncode != 0:
            raise subprocess.CalledProcessError(process.returncode, command, stdout=stdout, stderr=stderr)
        return stdout
    except subprocess.CalledProcessError as e:
        if scan_id and scan_id in active_processes:
            del active_processes[scan_id]
        return e.stderr
    except Exception as e:
        if scan_id and scan_id in active_processes:
            del active_processes[scan_id]
        return str(e)

def parse_nmap_xml_to_json(nmap_xml_output):
    root = ET.fromstring(nmap_xml_output)
    hosts_data = []

    for host in root.findall('host'):
        host_info = {}
        addr = host.find('address')
        if addr is not None:
            host_info['address'] = addr.get('addr')
            host_info['addrtype'] = addr.get('addrtype')

        hostnames = host.find('hostnames')
        if hostnames is not None:
            hostname_list = []
            for hn in hostnames.findall('hostname'):
                hostname_list.append({'name': hn.get('name'), 'type': hn.get('type')})
            if hostname_list:
                host_info['hostnames'] = hostname_list

        ports_data = []
        ports = host.find('ports')
        if ports is not None:
            for port in ports.findall('port'):
                port_info = {
                    'protocol': port.get('protocol'),
                    'portid': port.get('portid')
                }
                state = port.find('state')
                if state is not None:
                    port_info['state'] = state.get('state')
                    port_info['reason'] = state.get('reason')
                service = port.find('service')
                if service is not None:
                    port_info['service'] = service.get('name')
                    if service.get('product'):
                        port_info['product'] = service.get('product')
                    if service.get('version'):
                        port_info['version'] = service.get('version')
                    if service.get('extrainfo'):
                        port_info['extrainfo'] = service.get('extrainfo')
                
                scripts_output = []
                for script in port.findall('script'):
                    script_data = {
                        'id': script.get('id'),
                        'output': script.get('output')
                    }
                    # Handle tables and elements within script output if necessary
                    for elem in script:
                        if elem.tag == 'table':
                            table_data = {}
                            for field in elem.findall('elem'):
                                table_data[field.get('key')] = field.text
                            if table_data:
                                script_data['table'] = table_data
                        elif elem.tag == 'elem':
                            script_data[elem.get('key')] = elem.text
                    scripts_output.append(script_data)
                if scripts_output:
                    port_info['scripts'] = scripts_output
                
                ports_data.append(port_info)
        if ports_data: # Only add if there's actual data for the host
            host_info['ports'] = ports_data
        
        if host_info: # Only add if there's actual data for the host
            hosts_data.append(host_info)
            
    return hosts_data

def analyze_with_gemini(api_key, scan_data, scan_type, target, lang='en'):
    if not api_key:
        return "Error: AI Engine API key is missing."
    if not scan_data:
        return "No scan data to analyze."

    # Language-specific prompts
    prompts = {
        'en': {
            'intro': "You are a senior cybersecurity analyst. Your task is to provide a concise, structured analysis of the following scan results, identify key vulnerabilities, and offer actionable recommendations. The target language for the report is English.",
            'outro': """IMPORTANT: You are a senior cybersecurity analyst. Create a highly structured and professional report. DO NOT use introductory phrases like "Of course," or "Here is the report". Go directly to the report.\n\n            ### **Cybersecurity Analysis Report**\n\n            ---\n\n            ### **1. EXECUTIVE SUMMARY**\n\n            *   **Analysis Date:** {date}\n            *   **Analyst:** Senior Cybersecurity Analyst\n            *   **Target:** {target}\n            *   **Methodology:** Security Scan ({scan_type})\n            *   **Key Findings:** (A brief summary of the main findings and the overall risk level.)\n\n            ---\n\n            ### **2. VULNERABILITY FINDINGS & RECOMMENDATIONS**\n\n            (For each vulnerability, use the following format. Order by risk level from Critical to Low.)\n\n            #### **2.1. (Vulnerability Name)**\n\n            *   **Risk Level:** (Critical | High | Medium | Low)\n            *   **Technical Description:** (An in-depth technical description of the vulnerability, including affected ports, services, and versions.)\n            *   **Potential Risk:** (Explain possible attack scenarios and their business impact, such as data theft, system takeover, or service disruption.)\n            *   **Remediation Recommendations:**\n                *   **Tools Recommendation:** (Mention specific tools that can be used for verification or remediation, e.g., `nmap`, `metasploit`, `openssl`, etc.)\n                *   **Step-by-Step Technical Remediation:**\n                    1.  (Clear, actionable step 1)\n                    2.  (Step 2, etc.)\n\n            ---\n            (Repeat the format above for each vulnerability)\n\n            ### **3. CONCLUSION & NEXT STEPS**\n\n            *   **Conclusion:** (An overall summary of the target's security posture based on the findings.)\n            *   **Recommended Next Steps:** (Suggest next steps, such as re-testing, monitoring, or security policy review.)\n\n            """
        },
        'id': {
            'intro': "Anda adalah seorang analis keamanan siber senior. Tugas Anda adalah memberikan analisis yang ringkas dan terstruktur dari hasil pemindaian berikut, mengidentifikasi kerentanan utama, dan menawarkan rekomendasi yang dapat ditindaklanjuti. Bahasa target untuk laporan adalah Bahasa Indonesia.",
            'outro': """PENTING: Anda adalah seorang analis keamanan siber senior. Buat laporan yang sangat terstruktur dan profesional. JANGAN gunakan kata-kata pembuka seperti "Tentu," atau "Berikut adalah laporannya". Langsung ke laporan.\n\n            ### **Laporan Analisis Keamanan Siber**\n\n            ---\n\n            ### **1. RINGKASAN EKSEKUTIF**\n\n            *   **Tanggal Analisis:** {date}\n            *   **Analis:** Analis Keamanan Siber Senior\n            *   **Target:** {target}\n            *   **Metodologi:** Pemindaian Keamanan ({scan_type})\n            *   **Ringkasan Temuan:** (Ringkasan singkat temuan utama dan tingkat risiko keseluruhan.)\n\n            ---\n\n            ### **2. TEMUAN KERENTANAN & REKOMENDASI**\n\n            (Untuk setiap kerentanan, gunakan format berikut. Urutkan berdasarkan tingkat risiko dari Kritis hingga Rendah.)\n\n            #### **2.1. (Nama Kerentanan)**\n\n            *   **Tingkat Risiko:** (Kritis | Tinggi | Sedang | Rendah)\n            *   **Deskripsi Teknis:** (Deskripsi teknis yang mendalam tentang kerentanan, termasuk port, layanan, dan versi yang terpengaruh.)\n            *   **Potensi Risiko:** (Jelaskan skenario serangan yang mungkin terjadi dan dampak bisnisnya, seperti pencurian data, pengambilalihan sistem, atau gangguan layanan.)\n            *   **Remediasi Rekomendasi:**\n                *   **Rekomendasi Tools:** (Sebutkan tools spesifik yang dapat digunakan untuk verifikasi atau perbaikan, contoh: `nmap`, `metasploit`, `openssl`, etc.)\n                *   **Langkah-langkah Perbaikan Teknis (Tahap demi Tahap):**\n                    1.  (Langkah pertama yang jelas dan dapat ditindaklanjuti)\n                    2.  (Langkah kedua, dst.)\n\n            ---\n            (Ulangi format di atas untuk setiap kerentanan)\n
            ### **3. KESIMPULAN & LANGKAH SELANJUTNYA**\n\n            *   **Kesimpulan:** (Ringkasan keseluruhan postur keamanan target berdasarkan temuan.)\n            *   **Langkah Selanjutnya yang Direkomendasikan:** (Saran langkah-langkah berikutnya, seperti pengujian ulang, pemantauan, atau tinjauan kebijakan keamanan.)\n\n            """
        }
    }

    selected_prompt = prompts.get(lang, prompts['en']) # Default to English

    # Add specific instruction for nslookup if it's the scan type
    nslookup_instruction = ""
    if scan_type == 'nslookup':
        if lang == 'id':
            nslookup_instruction = "Harap analisis output nslookup ini. Jika menunjukkan 'NXDOMAIN' atau 'tidak dapat menemukan', jelaskan implikasinya (misalnya, tidak ada catatan DNS, atau resolusi DNS gagal) dan berikan rekomendasi terkait."
        elif lang == 'jv':
            nslookup_instruction = "Tulung analisis output nslookup iki. Yen nuduhake 'NXDOMAIN' utawa 'ora bisa nemokake', jlentrehake implikasine (contone, ora ana cathetan DNS, utawa resolusi DNS gagal) lan wenehi rekomendasi sing gegandhengan."
        elif lang == 'th':
            nslookup_instruction = "โปรดวิเคราะห์ผลลัพธ์ nslookup นี้ หากแสดง 'NXDOMAIN' หรือ 'ไม่พบ' โปรดอธิบายความหมาย (เช่น ไม่มีระเบียน DNS หรือการแก้ไข DNS ล้มเหลว) และให้คำแนะนำที่เกี่ยวข้อง)"
        else: # Default to English
            nslookup_instruction = "Please analyze this nslookup output. If it indicates 'NXDOMAIN' or 'can\'t find', explain the implications (e.g., no DNS record, or DNS resolution failed) and provide relevant recommendations."

    # Ensure scan_data is always a JSON string for consistent AI input
    formatted_scan_data = json.dumps(scan_data, indent=2) if isinstance(scan_data, (dict, list)) else json.dumps(str(scan_data), indent=2)

    prompt = f"""
    {selected_prompt['intro']}
    {nslookup_instruction}
    Scan Type: {scan_type}
    Scan Data:
    ```json
    {formatted_scan_data}
    ```
    {selected_prompt['outro'].format(target=target, scan_type=scan_type, date=datetime.now().strftime("%d %B %Y"))}
    """

    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-pro-latest')
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        return f"Error during AI Engine analysis: {str(e)}"

# --- Asynchronous Scan Logic ---
def perform_scan_and_analyze(scan_id, target, ports, ai_api_key, scan_type, lang):
    # Note: The original code wrote to a specific log file path.
    # For modularity, this path should ideally be configurable or relative.
    # For now, I'll keep the original path for simplicity during refactoring.
    with open("/usr/lib/gemini-cli/vulnerability_scanner/thread_debug.log", "a") as f:
        try:
            f.write(f"[{datetime.now()}] THREAD {scan_id}: Starting.\n")
            global scan_results_store, cancellation_flags, active_processes

            cancellation_flags[scan_id] = threading.Event()
            scan_results_store[scan_id] = {'status': 'running', 'progress': 'Starting scan...'}
            f.write(f"[{datetime.now()}] THREAD {scan_id}: Initial status set.\n")
            f.write(f"[{datetime.now()}] THREAD {scan_id}: Received API Key (masked): {ai_api_key if ai_api_key else '[EMPTY/NONE]'}\n")

            sanitized_target = shlex.quote(target)
            scan_results = None
            command_map = {
                'ping': ['ping', '-c', '4', sanitized_target],
                'traceroute': ['traceroute', sanitized_target],
                'nslookup': ['nslookup', sanitized_target],
                'nmap_vuln': ['nmap', '--script', 'vuln', '-sV', sanitized_target],
                'subdomain_enum': ['nmap', '--script', 'dns-brute', sanitized_target],
                'http_enum': ['nmap', '--script', 'http-enum', '-sV', sanitized_target]
            }

            if cancellation_flags[scan_id].is_set():
                raise InterruptedError("Scan cancelled by user.")

            f.write(f"[{datetime.now()}] THREAD {scan_id}: Starting scan type {scan_type}.\n")
            if scan_type == 'nmap':
                scan_results_store[scan_id]['progress'] = 'Running Nmap scan...'
                nm = nmap.PortScanner()
                nmap_args = '-sV'
                if ports:
                    sanitized_ports = re.sub(r'[^0-9,-]', '', ports)
                    nmap_args += f' -p {sanitized_ports}'
                if cancellation_flags[scan_id].is_set():
                    raise InterruptedError("Scan cancelled by user.")
                nm.scan(hosts=sanitized_target, arguments=nmap_args)
                scan_results_xml = nm.get_nmap_last_output()
                scan_results = parse_nmap_xml_to_json(scan_results_xml)
            elif scan_type in command_map:
                scan_results_store[scan_id]['progress'] = f'Running {scan_type} command...'
                scan_results = run_command(command_map[scan_type], scan_id)
            else:
                raise ValueError('Invalid scan type')
            f.write(f"[{datetime.now()}] THREAD {scan_id}: Scan logic finished.\n")

            if cancellation_flags[scan_id].is_set():
                raise InterruptedError("Scan cancelled by user.")

            scan_results_store[scan_id]['progress'] = 'Analyzing results with AI Engine...'
            f.write(f"[{datetime.now()}] THREAD {scan_id}: Calling analyze_with_gemini.\n")
            ai_analysis = analyze_with_gemini(ai_api_key, scan_results, scan_type, target, lang)
            f.write(f"[{datetime.now()}] THREAD {scan_id}: Got AI analysis (first 100 chars): {ai_analysis[:100]}...\n")

            scan_results_store[scan_id].update({
                'status': 'completed',
                'scan_results': scan_results,
                'ai_analysis': ai_analysis,
                'target': target,
                'scan_type': scan_type,
                'progress': 'Analysis complete.'
            })
            f.write(f"[{datetime.now()}] THREAD {scan_id}: Stored final results.\n")

        except Exception as e:
            import traceback
            f.write(f"[{datetime.now()}] !!! THREAD {scan_id}: EXCEPTION CAUGHT !!!\n")
            f.write(f"Error: {str(e)}\n")
            traceback.print_exc(file=f)
            f.write("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n")
            scan_results_store[scan_id].update({
                'status': 'error',
                'error': f"Thread failed: {str(e)}",
                'progress': 'Scan failed in thread.'
            })
        finally:
            f.write(f"[{datetime.now()}] THREAD {scan_id}: Finally block reached.\n")
            if scan_id in cancellation_flags:
                del cancellation_flags[scan_id]
            if scan_id in active_processes:
                del active_processes[scan_id]

def perform_config_analysis(config_id, device_type, host, username, password, api_key):
    global scan_results_store, config_cancellation_flags
    config_cancellation_flags[config_id] = threading.Event()
    scan_results_store[config_id] = {'status': 'running', 'progress': 'Starting config analysis...'}

    try:
        if not all([device_type, host, username, password, api_key]):
            raise ValueError('All fields are required: Device Type, Host, Username, Password, and API Key.')

        # Define command based on device type
        if device_type == 'mikrotik':
            command = '/export'
            prompt_intro = "You are a senior network security architect specializing in MikroTik devices. Analyze the following MikroTik configuration export."
        elif device_type == 'cisco_ios':
            command = 'show running-config'
            prompt_intro = "You are a senior network security architect specializing in Cisco IOS devices. Analyze the following Cisco 'show running-config' output."
        else:
            raise ValueError('Unsupported device type.')

        config_data = ''
        error_data = ''
        try:
            if config_cancellation_flags[config_id].is_set():
                raise InterruptedError("Config analysis cancelled by user.")

            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_client.connect(hostname=host, username=username, password=password, timeout=15, banner_timeout=20)
            
            if config_cancellation_flags[config_id].is_set():
                raise InterruptedError("Config analysis cancelled by user.")

            if device_type == 'cisco_ios': # Handle pagination for Cisco
                channel = ssh_client.invoke_shell()
                channel.send('terminal length 0\n')
                channel.send(command + '\n')
                import time
                time.sleep(5) # Wait for the command to complete
                channel.send('exit\n')
                output = channel.recv(65535).decode('utf-8')
                # Clean up Cisco output
                lines = output.splitlines()
                start_index = -1
                end_index = -1
                for i, line in enumerate(lines):
                    if "Current configuration" in line:
                        start_index = i + 1
                    elif line.strip() == 'end' and start_index != -1:
                        end_index = i
                        break
                if start_index != -1 and end_index != -1:
                    config_data = '\n'.join(lines[start_index:end_index])
                else: # Fallback if parsing fails
                    config_data = output
            else: # For MikroTik and others
                stdin, stdout, stderr = ssh_client.exec_command(command)
                config_data = stdout.read().decode('utf-8')
                error_data = stderr.read().decode('utf-8')

            ssh_client.close()

        except paramiko.AuthenticationException:
            raise ValueError('Authentication failed: Please check your username and password.')
        except paramiko.SSHException as e:
            raise ValueError(f'SSH Connection Error: Could not connect to {host}. Ensure the host is reachable, SSH is enabled, and credentials are correct. Details: {str(e)}')
        except Exception as e:
            raise ValueError(f'An unexpected error occurred during SSH connection: {str(e)}')

        if error_data:
            raise ValueError(f'Error executing command on device: {error_data}')
        if not config_data:
            raise ValueError('Failed to retrieve configuration: The command returned no data. Check device compatibility and command execution.')

        if config_cancellation_flags[config_id].is_set():
            raise InterruptedError("Config analysis cancelled by user.")

        # Prompt for Gemini
        model = genai.GenerativeModel('gemini-pro-latest')

        # Language-specific structured output formats
        structured_output_formats = {
            'en': """
            Provide your analysis in this format:\n\n            ### 🛡️ Security Analysis\n            (List all potential security risks, such as weak passwords, open ports, insecure services, firewall rule issues, etc.)\n\n            ### ⚙️ Configuration Best Practices\n            (List recommendations for improving the configuration based on best practices, e.g., disabling unused services, proper IPsec setup, etc.)\n\n            ### 🚀 Performance Tuning\n            (Suggest changes that could improve the device's performance, like optimizing queues or firewall rules.)\n\n            ### 📝 Summary\n            (A brief, high-level summary of the device's overall health.)\n            """,
            'id': """
            Sajikan analisis Anda dalam format ini:\n\n            ### 🛡️ Analisis Keamanan\n            (Daftar semua potensi risiko keamanan, seperti kata sandi lemah, port terbuka, layanan tidak aman, masalah aturan firewall, dll.)\n\n            ### ⚙️ Praktik Terbaik Konfigurasi\n            (Daftar rekomendasi untuk meningkatkan konfigurasi berdasarkan praktik terbaik, mis. menonaktifkan layanan yang tidak digunakan, pengaturan IPsec yang tepat, dll.)\n\n            ### 🚀 Penyetelan Kinerja\n            (Sarankan perubahan yang dapat meningkatkan kinerja perangkat, seperti mengoptimalkan antrean atau aturan firewall.)\n\n            ### 📝 Ringkasan\n            (Ringkasan singkat dan tingkat tinggi tentang kesehatan perangkat secara keseluruhan.)\n            """,
            'jv': """
            Sajikake analisis sampeyan ing format iki:\n\n            ### 🛡️ Analisis Keamanan\n            (Daftar kabeh potensi risiko keamanan, kayata sandhi sing ringkih, port sing mbukak, layanan sing ora aman, masalah aturan firewall, lsp.)\n\n            ### ⚙️ Praktik Paling Apik Konfigurasi\n            (Daftar rekomendasi kanggo nambah konfigurasi adhedhasar praktik paling apik, contone, mateni layanan sing ora digunakake, persiyapan IPsec sing tepat, lsp.)\n\n            ### 🚀 Penyetelan Kinerja\n            (Saranake owah-owahan sing bisa nambah kinerja piranti, kayata ngoptimalake antrean utawa aturan firewall.)\n\n            ### 📝 Ringkesan\n            (Ringkesan singkat lan tingkat dhuwur babagan kesehatan piranti sakabèhé.)\n            """,
            'th': """
            จัดทำรายงานการวิเคราะห์ของคุณในรูปแบบนี้:\n\n            ### 🛡️ การวิเคราะห์ความปลอดภัย\n            (แสดงรายการความเสี่ยงด้านความปลอดภัยที่อาจเกิดขึ้นทั้งหมด เช่น รหัสผ่านที่อ่อนแอ, พอร์ตที่เปิดอยู่, บริการที่ไม่ปลอดภัย, ปัญหาเกี่ยวกับกฎไฟร์วอลล์ ฯลฯ)\n\n            ### ⚙️ แนวทางปฏิบัติที่ดีที่สุดในการกำหนดค่า\n            (แสดงรายการคำแนะนำสำหรับการปรับปรุงการกำหนดค่าตามแนวทางปฏิบัติที่ดีที่สุด เช่น การปิดใช้งานบริการที่ไม่ได้ใช้, การตั้งค่า IPsec ที่เหมาะสม ฯลฯ)\n\n            ### 🚀 การปรับแต่งประสิทธิภาพ\n            (แนะนำการเปลี่ยนแปลงที่สามารถปรับปรุงประสิทธิภาพของอุปกรณ์ เช่น การเพิ่มประสิทธิภาพคิวหรือกฎไฟร์วอลล์)\n\n            ### 📝 สรุป\n            (สรุปโดยย่อและระดับสูงเกี่ยวกับสถานะสุขภาพโดยรวมของอุปกรณ์)\n            """
        }

        selected_structured_output = structured_output_formats.get(lang, structured_output_formats['en']) # Default to English

        prompt = f"""
        {prompt_intro}
        Identify security vulnerabilities, misconfigurations, and areas for performance improvement.
        Provide a structured analysis with clear, actionable recommendations. Use markdown for formatting.

        Configuration Data:
        ---
        {config_data}
        ---
        {selected_structured_output}
        """

        response = model.generate_content(prompt)
        
        scan_results_store[config_id].update({
            'status': 'completed',
            'config_data': config_data,
            'ai_analysis': response.text,
            'progress': 'Analysis complete.'
        })

    except InterruptedError:
        scan_results_store[config_id].update({
            'status': 'cancelled',
            'error': 'Config analysis cancelled by user.',
            'progress': 'Config analysis cancelled.'
        })
    except ValueError as e:
        scan_results_store[config_id].update({
            'status': 'error',
            'error': str(e),
            'progress': 'Config analysis failed.'
        })
    except Exception as e:
        scan_results_store[config_id].update({
            'status': 'error',
            'error': f'An internal server error occurred: {str(e)}',
            'progress': 'Config analysis failed.'
        })
    finally:
        if config_id in config_cancellation_flags:
            del config_cancellation_flags[config_id]

def perform_log_analysis_async(log_id, log_data, api_key, lang):
    global scan_results_store, cancellation_flags
    cancellation_flags[log_id] = threading.Event() # Use general cancellation flag for log analysis too
    try:
        if cancellation_flags[log_id].is_set():
            raise InterruptedError("Log analysis cancelled by user.")

        scan_results_store[log_id]['progress'] = 'Analyzing log data with AI Engine...'
        
        # Use the existing analyze_with_gemini function
        ai_analysis = analyze_with_gemini(api_key, log_data, "Log Analysis", lang)

        scan_results_store[log_id].update({
            'status': 'completed',
            'raw_log_data': log_data, # Store raw log data
            'ai_analysis': ai_analysis,
            'progress': 'Analysis complete.'
        })

    except InterruptedError:
        scan_results_store[log_id].update({
            'status': 'cancelled',
            'error': 'Log analysis cancelled by user.',
            'progress': 'Log analysis cancelled.'
        })
    except Exception as e:
        scan_results_store[log_id].update({
            'status': 'error',
            'error': str(e),
            'progress': 'Log analysis failed.'
        })
    finally:
        if log_id in cancellation_flags:
            del cancellation_flags[log_id]

def chat_with_gemini(api_key, history, lang='en'):
    if not api_key:
        return "Error: AI Engine API key is missing."
    if not history:
        return "No conversation history to analyze."

    genai.configure(api_key=api_key)
    model = genai.GenerativeModel('gemini-pro-latest')

    # The prompt is the conversation history
    prompt = ""
    for message in history:
        role = message['role']
        text = message['parts'][0]['text']
        prompt += f"{role}: {text}\n"

    try:
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        return f"Error during AI Engine analysis: {str(e)}"
