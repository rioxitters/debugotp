const JavaScriptObfuscator = require('javascript-obfuscator');
const fs = require('fs');
const path = require('path');

const publicDir = path.join(__dirname, 'public');

function obfuscateFile(filePath) {
    const code = fs.readFileSync(filePath, 'utf8');
    const result = JavaScriptObfuscator.obfuscate(code, {
        compact: true,
        controlFlowFlattening: true,
        controlFlowFlatteningThreshold: 1,
        numbersToExpressions: true,
        simplify: true,
        stringArrayThreshold: 1,
        splitStrings: true,
        splitStringsChunkLength: 5,
        unicodeEscapeSequence: false
    });
    fs.writeFileSync(filePath, result.getObfuscatedCode());
}

function processDirectory(dir) {
    const files = fs.readdirSync(dir);
    files.forEach(file => {
        const filePath = path.join(dir, file);
        if (fs.statSync(filePath).isDirectory()) {
            processDirectory(filePath);
        } else if (filePath.endsWith('.js') && !filePath.includes('min.js')) {
            console.log(`Obfuscating: ${filePath}`);
            obfuscateFile(filePath);
        }
    });
}

console.log('🚀 Starting Frontend Code Obfuscation...');
processDirectory(publicDir);
console.log('✅ Obfuscation Complete!');
