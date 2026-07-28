const fs = require('fs');
const code = fs.readFileSync('server.js', 'utf8');

// Extract DOMAIN_TO_PROVIDER
const match = code.match(/const DOMAIN_TO_PROVIDER = \{([\s\S]+?)\n\};/);
if (match) {
  const mapStr = '{' + match[1] + '\n}';
  const DOMAIN_TO_PROVIDER = eval('(' + mapStr + ')');
  
  console.log('=== Testing provider detection ===');
  
  const testEmails = [
    'test@comcast.com',
    'test@comcast.net',
    'test@xfinity.com',
    'test@gmail.com',
    'test@outlook.com',
  ];
  
  testEmails.forEach(email => {
    const domain = email.split('@')[1];
    const provider = DOMAIN_TO_PROVIDER[domain];
    console.log(`${email} => domain: ${domain} => provider: ${provider}`);
  });
}
