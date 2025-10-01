# Neti Beta 02 Application

## Deskripsi Proyek
Aplikasi Neti Beta 02 adalah sebuah platform berbasis Flask yang dirancang untuk melakukan analisis keamanan siber, termasuk pemindaian jaringan, analisis log, dan analisis konfigurasi perangkat, dengan bantuan AI Engine (Gemini).

## Fitur Utama
- Pemindaian Jaringan (Nmap, Ping, Traceroute, Nslookup)
- Analisis Log
- Analisis Konfigurasi Perangkat Jaringan (MikroTik, Cisco IOS)
- Integrasi dengan AI Engine untuk analisis mendalam dan rekomendasi.

## Persyaratan
- Python 3.x
- pip (Python package installer)
- Virtual Environment (direkomendasikan)
- Nmap (untuk fitur pemindaian jaringan)
- Akses ke Gemini API (untuk fitur analisis AI)

## Instalasi

### 1. Clone Repositori
```bash
git clone <URL_REPOSITORI_ANDA_DI_GIT.BRIN.GO.ID>
cd neti_beta_02
```

### 2. Buat dan Aktifkan Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Instal Dependensi
```bash
pip install -r requirements.txt
```

### 4. Konfigurasi
Edit `config.py` untuk mengatur `SECRET_KEY` dan `API_KEY` Anda.
```python
# neti_beta_02/config.py
import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-super-secret-key'
    API_KEY = os.environ.get('API_KEY') # Ganti dengan kunci API Gemini Anda
    # Tambahkan variabel konfigurasi lainnya di sini
```

## Menjalankan Aplikasi

### Mode Pengembangan (Manual)
```bash
source venv/bin/activate
python run.py
```
Aplikasi akan berjalan di `http://127.0.0.1:5002` atau `http://0.0.0.0:5002`.

### Sebagai Layanan Systemd (Direkomendasikan untuk Produksi)
Aplikasi ini dapat dijalankan sebagai layanan systemd, yang akan otomatis dimulai saat boot dan di-restart jika terjadi crash.

1.  **Buat File Service:**
    Buat file `/etc/systemd/system/neti_beta_02.service` dengan konten berikut (pastikan untuk mengganti `User` dan `Group` dengan yang sesuai):
    ```ini
    [Unit]
    Description=Neti Beta 02 Flask Application
    After=network.target

    [Service]
    User=your_username_here  ; Ganti dengan username Anda
    Group=your_group_here    ; Ganti dengan group Anda
    WorkingDirectory=/usr/lib/gemini-cli/neti_beta_02
    ExecStart=/usr/lib/gemini-cli/neti_beta_02/venv/bin/python run.py
    Restart=always

    [Install]
    WantedBy=multi-user.target
    ```
    *Catatan: Anda sudah memiliki file ini di `/usr/lib/gemini-cli/neti_beta_02.service` dan sudah dikonfigurasi dengan `User=root` dan `Group=root`.*

2.  **Salin dan Aktifkan Layanan:**
    ```bash
    sudo cp /usr/lib/gemini-cli/neti_beta_02.service /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable neti_beta_02.service
    sudo systemctl start neti_beta_02.service
    ```

3.  **Manajemen Layanan (Menggunakan Skrip):**
    Anda dapat menggunakan skrip `manage_neti_beta_02.sh` yang sudah dibuat:
    ```bash
    /usr/lib/gemini-cli/manage_neti_beta_02.sh status
    /usr/lib/gemini-cli/manage_neti_beta_02.sh restart
    /usr/lib/gemini-cli/manage_neti_beta_02.sh stop
    /usr/lib/gemini-cli/manage_neti_beta_02.sh start
    ```

## Penggunaan
Akses aplikasi melalui browser Anda di `http://<IP_SERVER_ANDA>:5002`.

## Pengembangan
1.  Pastikan virtual environment aktif (`source venv/bin/activate`).
2.  Lakukan perubahan pada kode sumber.
3.  Jalankan tes (jika ada).
4.  Untuk melihat perubahan, restart aplikasi (jika berjalan sebagai layanan systemd, gunakan `sudo systemctl restart neti_beta_02.service`).

## Kontribusi
Silakan ajukan isu atau pull request di repositori Git internal Anda (`git.brin.go.id`).

## Lisensi
Proyek ini dilisensikan di bawah MIT License. Lihat file [LICENSE](LICENSE) untuk detail lebih lanjut.
