#!/bin/bash
echo ""
echo "  ========================================"
echo "   Control Center - One-Click Installer"
echo "  ========================================"
echo ""

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "  [*] Installing Node.js..."
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
    sudo apt install -y nodejs
fi
echo "  [+] Node.js: $(node --version)"

# Install dependencies
echo ""
echo "  [*] Installing dependencies..."
npm install --production
echo "  [+] Dependencies installed."

# Generate session secret if default
echo ""
if grep -q "change_this" .env 2>/dev/null; then
    SECRET=$(node -e "console.log(require('crypto').randomBytes(48).toString('hex'))")
    sed -i "s/change_this_to_random_64_chars/$SECRET/" .env
    echo "  [+] Session secret generated."
else
    echo "  [+] Session secret already set."
fi

# Run obfuscator
echo ""
echo "  [*] Obfuscating frontend code..."
node obfuscate.js
echo "  [+] Obfuscation complete."

# Open firewall
echo ""
echo "  [*] Opening firewall port 3000..."
sudo ufw allow 3000 2>/dev/null || sudo firewall-cmd --add-port=3000/tcp --permanent 2>/dev/null && sudo firewall-cmd --reload 2>/dev/null
echo "  [+] Firewall configured."

# Install PM2
echo ""
echo "  [*] Installing PM2..."
sudo npm install -g pm2
echo "  [+] PM2 installed."

# Start with PM2
echo ""
echo "  [*] Starting server..."
pm2 delete panel 2>/dev/null
pm2 start server.js --name panel
pm2 save
pm2 startup | tail -1 | bash 2>/dev/null

echo ""
echo "  ========================================"
echo "   INSTALLATION COMPLETE"
echo "  ========================================"
echo ""
echo "  Server: http://$(curl -s ifconfig.me 2>/dev/null || echo localhost):3000"
echo "  Admin:  http://$(curl -s ifconfig.me 2>/dev/null || echo localhost):3000/u/login"
echo ""
echo "  Commands:"
echo "    pm2 logs panel     - View logs"
echo "    pm2 restart panel  - Restart"
echo "    pm2 stop panel     - Stop"
echo ""
